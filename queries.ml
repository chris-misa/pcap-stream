open Printf
open Utils
open Pcap_stream


(* Sonata 1 *)
let tcp_new_cons s =
    let threshold = 1 in
    s
    |> epoch 1.0
    |> filter (fun p ->
            (find_int "ipv4.proto" p) = 6 &&
            (find_int "l4.flags" p) = 2)
    |> groupby (filter_keys ["ipv4.dst"]) count "cons"
    |> filter (fun p -> (find_int "cons" p) >= threshold)

let current_query = tcp_new_cons

let process_file file_name query =
    (of_pcap_file file_name)
    |> query
    |> dump stdout

let () = 
    if Array.length Sys.argv = 2
    then process_file Sys.argv.(1) current_query
    else printf "Expected <pcap file path> as argument."
