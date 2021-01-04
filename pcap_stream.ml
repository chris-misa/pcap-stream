(*
 * Stream processing on pcap files
 * Based on Streaming module (https://github.com/odis-labs/streaming)
 *)

open Streaming

open Utils

(* Bring filter and map into scope *)
let filter f = Stream.filter (fun p -> Tuple.mem "epoch" p || f p)
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

let split_on_epoch last_eid s =
    s
    |> Stream.split ~by:(fun p ->
        match Tuple.find_opt "epoch" p with
            | Some (Int eid) -> (last_eid := eid ; true)
            | _ -> false
    )

let groupby (k : tuple -> tuple) (f : op_result -> tuple -> op_result) (res_key : string) (s : tuple stream) : tuple stream =
    let last_eid = ref 0 in
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
        |> Stream.append (tuple_of_list [("epoch", Int !last_eid)])
    )

(* BROKEN *)
let split s_in =
    let clone s =
        Stream.unfold s (fun s ->
            match Stream.first s with (* the problem is this consumes s! *)
                | Some a -> Some (a, Stream.prepend a s) (* then this just reverse the progress *)
                | None -> None
        )
    in (clone s_in, clone s_in)

(* this can probably be simplified a bunch by
1. Converting the two input streams to sources (use Source.unfold as below generically)
2. using Source.zip_with 
*)
let join (lkey : tuple -> (tuple * tuple)) (rkey : tuple -> (tuple * tuple)) l r =
    let ltbl = Hashtbl.create init_table_size in
    let rtbl = Hashtbl.create init_table_size in
    let proc_one m m' f p_opt =
        match p_opt with
            | Some p -> (
                let k, v = f p in
                match Hashtbl.find_opt m' k with
                    | Some v' ->
                        let use_left = fun _ a _ -> Some a in
                        Some (Tuple.union use_left k (Tuple.union use_left v v'))
                    | None -> (
                        Hashtbl.replace m k v;
                        None
                    )
            )
            | None -> None
    in
    (* Merge left and right strings into a stream of (left,right) tuples *)
    Stream.from (
        Source.unfold (l,r) (fun (l, r) ->
            match (Stream.first l, Stream.first r) with (* Don't need Stream.rest l/r? *)
                | (Some a, Some b) -> Some ((Some a, Some b), (l, r))
                | (Some a, None) -> Some ((Some a, None), (l, r))
                | (None, Some b) -> Some ((None, Some b), (l, r))
                | (None, None) -> None
        )
    )
    (* Apply processing for packets in both left and right streams, merging results *)
    |> Stream.flat_map (fun (a, b) ->
        match (proc_one ltbl rtbl lkey a, proc_one rtbl ltbl rkey b) with
            | (Some lres, Some rres) -> Stream.double lres rres
            | (Some lres, None) -> Stream.single lres
            | (None, Some rres) -> Stream.single rres
            | (None, None) -> Stream.empty
    )
        

    
    

(*

Probably need good/better utils for abstracting actions around tuples
- field access
- modifying field values
- changing keys

join:
    split each stream by epoch markers
    fold each stream,epoch into hashtbl
    emit matching between hashtbls as result stream

... can do the thing where we keep table of key,value for each input, then emit tuple on match from either stream's process ... the issue if how to merge the resulting two match streams.


Idea 2:

both streams feed into respective hash tables.


Idea 3:

Hack to get interleaving:

let merge l r =
    Source.unfold (l,r) (fun (l, r) ->
        match (Stream.first l, Stream.first r) with
            | (Some a, Some b) -> Some ((a,b), (Stream.rest l, Stream.rest r))
            | _ -> None
    )

... like a classic element-wise zip

let zipper l r =
    Source.unfold (l,r) (fun (l,r) ->
        match (Stream.first l, Stream.first r) with
            | (Some a, _) -> Some (a, (Stream.rest l, r))
            | (_, Some a) -> Some (a, (l, Stream.rest r))
            | (None, None) -> None
    )

... yeilds stream with all the elements of l followed by all the elements of r

*)

