open Cmdliner
open Containers

let printf = Printf.printf

module CBOR = Containers_cbor

(* When detecting nested cbor, we really don't want to allow arbitrary CBOR, but
   only maps and arrays. This helps a little bit. *)
let is_sane (cbor: CBOR.t) = match cbor with
  | `Array _ -> true
  | `Map _ -> true
  | _ -> false

let is_printable ch =
  Char.compare ch ' ' >= 0 && Char.compare ch '~' <= 0

let walk (cbor : CBOR.t) =
  let indent level =
    for _ = 1 to level do
      printf "    "
    done in
  let rec walk ?(level = 0) (cbor : CBOR.t) =
    let nlevel = level + 1 in
    match cbor with
    | `Tag (n, sub) ->
      printf "%d(\n" n;
      indent nlevel; walk ~level:nlevel sub;
      printf "\n";
      indent level; printf ")";
    | `Array elts ->
      printf "[\n";
      let show_elt elt =
        indent nlevel;
        walk ~level:nlevel elt;
        printf ",\n" in
      List.iter show_elt elts;
      indent level; printf "]"
    | `Map elts ->
      printf "{\n";
      let show_elt (k, v) =
        indent nlevel;
        walk ~level:nlevel k;
        printf ": ";
        walk ~level:nlevel v;
        printf ",\n" in
      List.iter show_elt elts;
      indent level; printf "}";
    | `Int ii ->
      printf "%Ld" ii
    | `Bytes b ->
      (* Attempt to decode the bytes into additional cbor, if that works, print in
         nested notation. *)
      begin match CBOR.decode b with
        | Result.Ok sub when is_sane sub ->
          printf "<<\n";
          indent nlevel;
          walk ~level:nlevel sub;
          printf "\n";
          indent level; printf ">>"
        | _ ->
          if String.for_all is_printable b then
            printf "b%S" b
          else begin
            printf "h\'";
            String.iter (fun ch -> printf "%02X" (Char.to_int ch)) b;
            printf "'"
          end
      end
    | `Text t ->
      printf "%S" t
    | _ -> printf "todo"
  in walk cbor; printf "\n"

let diagprint name =
  let buf = match name with
    | Some name ->
      IO.with_in name IO.read_all
    | None -> failwith "TODO: no file specified"
  in
  let buf = buf |> CBOR.decode |> Result.get_or_failwith in
  walk buf

let filename =
  let doc = "The name of the cbor file to read." in
  Arg.(value &  opt (some file) None & info ["f"; "file"] ~docv:"FILE" ~doc)
  (* Arg.(required & pos 0 (some file) None & info [] ~docv:"NAME" ~doc) *)

let diagprint_t = Term.(const diagprint $ filename)

let cmd =
  let doc = "Pretty print a CBOR file in diag notation" in
  let man = [
    `S Manpage.s_bugs;
    `P "Email bug reports to <david.brown@linaro.org>."
  ] in
  let info = Cmd.info "diagprint" ~version:"%%VERSION%%" ~doc ~man in
  Cmd.v info diagprint_t

let main () = exit (Cmd.eval cmd)
let () = main ()
