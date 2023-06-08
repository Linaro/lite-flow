(* Decode the json in cose examples. *)

module Util = Yojson.Basic.Util

(* Read the example, and return the hex json. *)
let from_example fname =
  let js = Yojson.Basic.from_file fname in
  Util.(js |> member "output" |> member "cbor" |> to_string)
