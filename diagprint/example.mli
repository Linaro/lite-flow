(** Processing of COSE examples.

    The cose-examples repo has numerous examples that are stored in json files.
    The final CBOR is in these files and this module can extract that information.
*)

val from_example : string -> string
(** Read the example in the given filename, and return the hex representation of
    the encoded CBOR from the example. *)
