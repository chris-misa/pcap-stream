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

(* Sonata 5 *)
let ddos s =
    let threshold = 2 in
    s
    |> epoch 1.0
    |> groupby (filter_keys ["ipv4.src" ; "ipv4.dst"]) distinct ""
    |> groupby (filter_keys ["ipv4.dst"]) count "srcs"
    |> filter (fun p -> (find_int "srcs" p) >= threshold)

(* Sonata 7 *)
let completed_flows s =
    let threshold = 1 in
    let a, b =
        s
        |> filter (fun p -> (find_int "ipv4.proto" p) = 6)
        |> epoch 5.0 (* Adjusted *)
        |> fork in
    let syns =
        a
        |> filter (fun p -> (find_int "l4.flags" p) = 2)
        |> groupby (filter_keys ["ipv4.dst"]) count "syns" in
    let fins =
        b
        |> filter (fun p -> ((find_int "l4.flags" p) land 1) = 1)
        |> groupby (filter_keys ["ipv4.src"]) count "fins"
    in join
        (fun p -> (rename_keys [("ipv4.dst", "host")] p, filter_keys ["syns"] p))
        (fun p -> (rename_keys [("ipv4.src", "host")] p, filter_keys ["fins"] p))
        syns
        fins
    |> map (fun p -> Tuple.add "diff" (Int ((find_int "syns" p) - (find_int "fins" p))) p)
    |> filter (fun p -> (find_int "diff" p) >= threshold)
    
let fork_join_test s =
    let a, b = s |> epoch 1.0 |> fork in
    let syns = a |> filter (fun p -> (find_int "l4.flags" p) = 2) in
    let synacks = b |> filter (fun p -> (find_int "l4.flags" p) = 18) in
    join 
        (fun p -> (rename_keys [("ipv4.src","host")] p,rename_keys [("ipv4.dst","remote")] p))
        (fun p -> (rename_keys [("ipv4.dst","host")] p,filter_keys ["time"] p))
        syns synacks

let current_query = completed_flows

let process_file file_name query =
    (of_pcap_file file_name)
    |> query
    |> dump stdout

let () = 
    if Array.length Sys.argv = 2
    then process_file Sys.argv.(1) current_query
    else printf "Expected <pcap file path> as argument."
