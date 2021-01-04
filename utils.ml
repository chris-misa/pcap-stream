(*
 * Common utilities 
 *
 * Includes minimal parsing of header fields into a map from strings to values
 *)

open Printf
open Option

(*
 * Operators act on named "tuples" which are maps from strings to op_result types
 **************************************************************************************)

type op_result = 
    | Float of float
    | Int of int
    | IPv4 of Ipaddr.V4.t
    | MAC of Cstruct.t
    | Empty

module Tuple = Map.Make(String)
type tuple = op_result Tuple.t

(*
 * Conversion utilities
 **************************************************************************************)

let string_of_mac buf =
    let i n = Cstruct.get_uint8 buf n in
    sprintf "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
        (i 0) (i 1) (i 2) (i 3) (i 4) (i 5)

let tcp_flags_to_string flags =
    let module TCPFlagsMap = Map.Make(String) in
    let tcp_flags_map =
        TCPFlagsMap.of_seq (List.to_seq [
            ("FIN", 1 lsl 0);
            ("SYN", 1 lsl 1);
            ("RST", 1 lsl 2);
            ("PSH", 1 lsl 3);
            ("ACK", 1 lsl 4);
            ("URG", 1 lsl 5);
            ("ECE", 1 lsl 6);
            ("CWR", 1 lsl 7);
    ]) in TCPFlagsMap.(
        fold (fun k _ b -> if b = "" then k else b ^ "|" ^ k) (
            filter (fun _ m -> flags land m = m) tcp_flags_map
        ) ""
    )

let int_of_op_result r = match r with
    | Int i -> i
    | _ -> raise (Failure "Trying to extract int from non-int result")

let float_of_op_result r = match r with
    | Float f -> f
    | _ -> raise (Failure "Trying to exctract float from non-float result")

let string_of_op_result r = match r with
    | Float f -> sprintf "%f" f
    | Int i -> string_of_int i
    | IPv4 a -> Ipaddr.V4.to_string a
    | MAC m -> string_of_mac m
    | Empty -> "Empty"

let string_of_tuple (t : tuple) : string =
    Tuple.fold (fun k v str ->
        str ^ (sprintf "\"%s\" => %s, " k (string_of_op_result v))
    ) t ""

let tuple_of_list (l : (string * op_result) list) : tuple =
    Tuple.of_seq (List.to_seq l)

let dump_tuple outc t =
    fprintf outc "%s\n" (string_of_tuple t)

let find_int key t =
    int_of_op_result (Tuple.find key t)

let find_float key t =
    float_of_op_result (Tuple.find key t)

(*
 * Tuple key operations
 **************************************************************************************)

let filter_keys (keys : string list) (p : tuple) : tuple =
    Tuple.filter (fun k _ -> List.mem k keys) p

let rename_keys renamings (p : tuple) : tuple =
    let f k v a =
        List.find_map (fun (oldk, newk) ->
            if oldk = k
            then Some (Tuple.add newk v a)
            else None
        ) renamings 
    in
    Tuple.fold (fun k v a ->
        match f k v a with
            | Some new_a -> new_a
            | None -> a
    ) p Tuple.empty

(*
 * groupby aggregation functions
 **************************************************************************************)

let count (r : op_result) (_ : tuple) : op_result =
    match r with
        | Empty -> Int 1
        | Int i -> Int (i+1)
        | _ -> r

let distinct (r : op_result) (_ : tuple) : op_result =
    match r with
        | Empty -> Int 1
        | _ -> r



(*
 * Packet parsing utilities
 **************************************************************************************)

[%%cstruct
type ethernet = {
  dst: uint8_t [@len 6];
  src: uint8_t [@len 6];
  ethertype: uint16_t;
} [@@big_endian]]

[%%cstruct
type ipv4 = {
  hlen_version: uint8_t;
  tos: uint8_t;
  len: uint16_t;
  id: uint16_t;
  off: uint16_t;
  ttl: uint8_t;
  proto: uint8_t;
  csum: uint16_t;
  src: uint32_t;
  dst: uint32_t;
} [@@big_endian]]

[%%cstruct
type tcp = {
  src_port: uint16_t;
  dst_port: uint16_t;
  seqnum: uint32_t;
  acknum: uint32_t;
  offset_flags: uint16_t;
  window: uint16_t;
  checksum: uint16_t;
  urg: uint16_t;
} [@@big_endian]]

[%%cstruct
type udp = {
    src_port: uint16_t;
    dst_port: uint16_t;
    length: uint16_t;
    checksum: uint16_t;
} [@@big_endian]]

let parse_ethernet eth m =
    m |>
    (Tuple.add "eth.src" (MAC (get_ethernet_src eth))) |>
    (Tuple.add "eth.dst" (MAC (get_ethernet_dst eth))) |>
    (Tuple.add "eth.ethertype" (Int (get_ethernet_ethertype eth)))

let parse_ipv4 ip m = 
    m |>
    (Tuple.add "ipv4.hlen" (Int ((get_ipv4_hlen_version ip) land 0xF))) |>
    (Tuple.add "ipv4.proto" (Int (get_ipv4_proto ip))) |>
    (Tuple.add "ipv4.len" (Int (get_ipv4_len ip))) |>
    (Tuple.add "ipv4.src" (IPv4 (Ipaddr.V4.of_int32 (get_ipv4_src ip)))) |>
    (Tuple.add "ipv4.dst" (IPv4 (Ipaddr.V4.of_int32 (get_ipv4_dst ip))))

let parse_tcp tcp m = 
    m |>
    (Tuple.add "l4.sport" (Int (get_tcp_src_port tcp))) |>
    (Tuple.add "l4.dport" (Int (get_tcp_dst_port tcp))) |>
    (Tuple.add "l4.flags" (Int ((get_tcp_offset_flags tcp) land 0xFF)))

let parse_udp udp m =
    m |>
    (Tuple.add "l4.sport" (Int (get_udp_src_port udp))) |>
    (Tuple.add "l4.dport" (Int (get_udp_dst_port udp))) |>
    (Tuple.add "l4.flags" (Int 0))

let get_ip_version eth offset = 
    ((Cstruct.get_uint8 eth offset) land 0xF0) lsr 4

let parse_pkt network h hdr p = 
    let res = Tuple.empty in
    let module H = (val h: Pcap.HDR) in
    let time = (Int32.to_float (H.get_pcap_packet_ts_sec hdr))
            +. (Int32.to_float (H.get_pcap_packet_ts_usec hdr)) /. 1000000. in
    let res = Tuple.add "time" (Float time) res in
    let res, offset = (
        match network with
        | 1 -> ((parse_ethernet p res), sizeof_ethernet)
        | 101 -> (res, 0)
        | x -> failwith (sprintf "Unknown pcap network value: %d" x)
    ) in
    try
        let res, offset = (
            match get_ip_version p offset with
            | 4 ->
                    let res = parse_ipv4 (Cstruct.shift p offset) res in
                    (res, offset + ((int_of_op_result (Tuple.find "ipv4.hlen" res)) * 4))
            | _ -> raise (Invalid_argument "")
        ) in
        let res = (
            match int_of_op_result (Tuple.find "ipv4.proto" res) with
            | 6 -> parse_tcp (Cstruct.shift p offset) res
            | 17 -> parse_udp (Cstruct.shift p offset) res
            | _ -> raise (Invalid_argument "")
        ) in
        Some res
    with
        Invalid_argument _ -> None
            (* ...some packets in CAIDA traces are not as big as we expect which causes Cstruct to throw this: just ignore for now *)


(*
 * File handling utilities
 **************************************************************************************)

let open_file filename = 
    let fd = Unix.(openfile filename [O_RDONLY] 0) in
    let ba = Bigarray.(array1_of_genarray (Mmap.V1.map_file fd Bigarray.char c_layout false [|-1|])) in
    Cstruct.of_bigarray ba

let read_header filename =
    let buf = open_file filename in
    match Pcap.detect buf with
    | Some h -> h, buf
    | None -> failwith (sprintf "Failed to parse pcap header from %s" filename)


