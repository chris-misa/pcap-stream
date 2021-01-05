(*
 * Stream processing on pcap files
 * Based on Streaming module (https://github.com/odis-labs/streaming)
 *)

open Streaming

open Utils

let init_table_size = 1000

(* Make filter and map pass epoch markers *)
let filter f = Stream.filter (fun p -> (Tuple.mem "epoch" p) || (f p))
let map f = Stream.map (fun p ->
    match Tuple.mem "epoch" p with
        | true -> p
        | false -> f p
    )

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

(* Insert an epoch marker (i.e., a tuple with "epoch" and "time" fields) every dur seconds *)
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

let split_on_epoch last_eid s =
    s
    |> Stream.split ~by:(fun p ->
        match Tuple.find_opt "epoch" p with
            | Some _ -> (last_eid := p ; true)
            | _ -> false
    )

(* Form groups as determined by k, folding each group with f whose result is stored in res_key *)
let groupby (k : tuple -> tuple) (f : op_result -> tuple -> op_result) (res_key : string) (s : tuple stream) : tuple stream =
    let last_eid = ref Tuple.empty in
    s
    |> split_on_epoch last_eid
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
        |> Stream.append !last_eid
    )

(* Returns a tuple of streams with the same contents as s *)
let fork s = 
    let q1 = Queue.create () in
    let q2 = Queue.create () in
    let sink = Sink.make
        ~init:(fun () -> ())
        ~push:(fun () a -> (Queue.push a q1 ; Queue.push a q2 ; ()))
        ~full:(fun () -> false)
        ~stop:(fun () -> ())
        ()
    in s |> Stream.into sink;
    (Stream.from (Source.queue q1), Stream.from (Source.queue q2))

let interleave l r =
    let q1 = l |> Stream.into Sink.queue in
    let q2 = r |> Stream.into Sink.queue in
    Stream.(
    (Source.zip_with
        (fun a b -> Stream.double a b)
        (Source.queue q1)
        (Source.queue q2)
    |> Stream.from
    |> Stream.flatten)
    ++ (Source.queue q1 |> from)
    ++ (Source.queue q2 |> from)
    )

(* Inner join of l and r. The key functions produce key, value pairs where values from bot strings are passed on the output *)
let join (lkey : tuple -> (tuple * tuple)) (rkey : tuple -> (tuple * tuple)) l r =
    let ltbl = Hashtbl.create init_table_size in
    let rtbl = Hashtbl.create init_table_size in
    let proc_one m m' f p =
        let epoch = ref 0 in
        match Tuple.find_opt "epoch" p with
        | Some (Int e) -> (
            epoch := e + 1 ;
            Some p
        )
        | _ -> (
            let k, v = f p in
            let key = (Tuple.add "cur_epoch" (Int !epoch) k) in
            match Hashtbl.find_opt m' key with
                | Some v' -> (
                    let ul = fun _ a _ -> Some a in
                    Hashtbl.remove m' key;
                    Some (Tuple.union ul k (Tuple.union ul v v'))
                )
                | None -> (
                    Hashtbl.add m key v ;
                    None
                )
        )
    in
    interleave
        (l |> Stream.map (fun p -> (true,p)))
        (r |> Stream.map (fun p -> (false,p)))
    |> Stream.flat_map (fun lrp ->
        let one_res = match lrp with
            | (true,p) -> proc_one ltbl rtbl lkey p
            | (false,p) -> proc_one rtbl ltbl rkey p
        in match one_res with
            | Some p -> Stream.single p
            | None -> Stream.empty
    )
