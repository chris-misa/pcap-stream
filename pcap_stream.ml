(*
 * Stream processing on pcap files
 * Based on Streaming module (https://github.com/odis-labs/streaming)
 *)

open Printf
open Streaming

open Utils

(* Produce a stream of tuples parsed from headers in a given pcap file *)
let of_pcap_file (file_name : string) : tuple stream =
    let h, buf = read_header file_name in
    let module H = (val h: Pcap.HDR) in
    let header, body = Cstruct.split buf Pcap.sizeof_pcap_header in
    let network = Int32.to_int (H.get_pcap_header_network header) in
    let pkts_iter = Pcap.packets h body in
    let rec get_next_pkt () =
        match pkts_iter () with
            | Some (hdr, pkt) -> (
                match parse_pkt network h hdr pkt with
                    | Some p -> Some (p, ())
                    | None -> get_next_pkt ()
            )
            | None -> None
    in Stream.unfold () get_next_pkt

(* Utility for dumping all tuples to a given out_channel *)
let dump outc (s : tuple stream) : unit =
    s
    |> Stream.each (fun p -> dump_tuple outc p)

(* Insert a tuple with "epoch" => epoch_id, "time" => current time every dur seconds *)
let epoch (dur : float) (s : tuple stream) : tuple stream =
    let e = ref 0.0 in
    let eid = ref 0 in
    s
    |> Stream.flat_map (fun p ->
        let t = find_float "time" p in
        if !e = 0.0
        then (
            e := t +. dur ;
            Stream.single p
        ) else (
            let res = Stream.unfold () (fun () ->
                if t < !e
                then None
                else (
                    let res = Some (tuple_of_list [("epoch", Int !eid) ; ("time", Float !e)], ()) in
                    e := !e +. dur ;
                    incr eid ;
                    res
                )
            )
            in Stream.append p res
        )
    )

let init_table_size = 1000

let groupby (k : tuple -> tuple) (f : op_result -> tuple -> op_result) (res_key : string) (s : tuple stream) : tuple stream =
    let last_eid = ref 0 in
    s
    |> Stream.split ~by:(fun p ->
        match Tuple.find_opt "epoch" p with
            | Some (Int eid) -> (last_eid := eid ; true)
            | _ -> false
    )
    |> Stream.flat_map (fun epoch ->
        let m = Hashtbl.create init_table_size in
        (* Fold the stream for this epoch into a hash table using k and f *)
        epoch
        |> Stream.fold (fun () p ->
            let key = k p in
            match Hashtbl.find_opt m key with
                | Some v -> Hashtbl.replace m key (f v p)
                | None -> Hashtbl.add m key (f Empty p)
        ) () ;
        (* Fold the hash table back into a stream *)
        (Hashtbl.fold (fun k v s ->
            Stream.append (Tuple.add res_key v k) s
        ) m Stream.empty)
        |> Stream.append (tuple_of_list [("epoch", Int !last_eid)])
    )


(*

Probably need good/better utils for abstracting actions around tuples
- field access
- modifying field values
- changing keys

filter (built in now!)

map (built in now!)

epoch:
insert epoch boundary markers based on time values...


groupby:
    split by epoch markers
    fold each epoch into hashtbl
    emit hashtbl contents as result stream


join:
    split each stream by epoch markers
    fold each stream,epoch into hashtbl
    emit matching between hashtbls as result stream

*)
