open Cmdliner
open Containers

let printf = Printf.printf

type cbor_t = CBOR.Simple.t

(* CBOR decode that returns a Result instead of raising an exception. *)
let cbor_decode packet =
  try Result.Ok (CBOR.Simple.decode packet) with
  | CBOR.Error msg -> Result.Error msg

let is_printable ch =
  Char.compare ch ' ' >= 0 && Char.compare ch '~' <= 0

(** Indent to the given level. *)
let indent level =
  for _ = 1 to level do
    printf "    "
  done

let rec walk ?(level = 0) (cbor : cbor_t) =
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
    printf "%d" ii
  | `Bytes b ->
    (* Attempt to decode the bytes into additional cbor, if that works, print in
       nested notation. *)
    begin match cbor_decode b with
      | Result.Ok sub ->
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

let walk cbor = walk cbor; printf "\n"

(* Convert a hex string to binary.  This is fairly inefficient as it does a lot of allocations. *)
let unhex_block hex =
  let len = String.length hex in
  if len mod 2 <> 0 then failwith "Odd number of hex characters given";
  let result = Buffer.create (len / 2) in
  let rec loop pos =
    if pos >= len then Buffer.contents result else begin
      let chs = String.sub hex pos 2 in
      let value = int_of_string ("0x" ^ chs) in
      Buffer.add_int8 result value;
      loop (pos + 2)
    end in
  loop 0

(* Decode the two arguments, returning the raw cbor in either case. *)
let get_cbor name hex example =
  match (name, hex, example) with
  | (None, None, None) -> failwith "Must specify one of --file or --hex or --example"
  | (Some name, None, None) ->
    IO.with_in name IO.read_all
  | (None, Some hex, None) ->
    unhex_block hex
  | (None, None, Some example) ->
    unhex_block (Example.from_example example)
  | _ -> failwith "Must give either --file or --hex, not both"

let diagprint name hex example =
  let buf = get_cbor name hex example in
  let buf = buf |> cbor_decode |> Result.get_or_failwith in
  walk buf

let filename =
  let doc = "The name of the cbor file to read." in
  Arg.(value &  opt (some file) None & info ["f"; "file"] ~docv:"FILE" ~doc)
  (* Arg.(required & pos 0 (some file) None & info [] ~docv:"NAME" ~doc) *)

let hexarg =
  let doc = "Direct CBOR input as hex." in
  Arg.(value & opt (some string) None & info ["h"; "hex"] ~docv:"HEX" ~doc)

let examarg =
  let doc = "Read from a COSE example json file." in
  Arg.(value & opt (some file) None & info ["example"] ~docv:"EXAMPLE" ~doc)

let diagprint_t = Term.(const diagprint $ filename $ hexarg $ examarg)

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
