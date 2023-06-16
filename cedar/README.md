# The CEDAR protocol

The CEDAR protocol (COSE Encoding for Data At Rest) is a file format used to
securely communicate data between an embedded device and external entities that
wish to use that data.

## Overview

CEDAR is build around CBOR and COSE, and for the most part is a specification of
a specific application of COSE data. There are three packet types used to encode
data, a signed and encrypted payload packet, a session packet, and a smaller,
faster payload packet that uses the current session.

To avoid the added space of using additional user defined headers within COSE,
CEDAR wraps every packet in a simple CBOR array of two elements:

```
CEDAR_packet = [
   int,
   bstr,
]
```

More specifically the CEDAR packet is one of three packets:

```
CEDAR_packet = [
    ; CEDAR full payload
    1, bstr . COSE_Sign1,
] / [
    ; CEDAR Session
    2, bstr . COSE_Sign1,
] / [
    ; CEDAR session payload.
    3, bstr . COSE_Encrypt0,
]
```

## Protocol usage

There are two primary uses of CEDAR for transporting data from the embedded
device.  In both cases, it is necessary for some device provisioning to have
occurred. This provisioning is outside the scope of this document.

The cloud service will have an X.509 certificate and an associated private key
(only known to the cloud).

Each device will also have an X.509 certificate and its own private key.  These
certificates should be signed appropriately so that the necessary parties have
assurance that the certificates are trusted.  The details of this are beyond the
scope of CEDAR.

COSE uses a key identifier to distinguish keys, but doesn't otherwise specify
the format.  For CEDAR, we will use the textual representation of the Subject
field of the X.509 certificate.  Although this textual representation is not
canonically defined, use the guidelines in [RFC
4514](https://www.ietf.org/rfc/rfc4514.txt).  In the messages below, "sender"
will refer to the device, and specifically the device's X.509 certificate, and
"recipient" will refer to the cloud service, and it's X.509 certificate.

### Full payload

There are instances where a device will need to encrypt/sign a single message
that is not in the context of a larger set of communication.  This, for example,
can be used to indicate configuration or environmental changes.  In this case,
the device should use the CEDAR full payload packet.  This packet contains an
encrypted payload, as well as a signature by the device of it's authenticity.
Note that the overhead for the signature is significant (often 100s of ms), so
this should only be used for infrequently sent data.

### Session data

Because of the overhead of digital signatures, a device can sent larger amounts
of data by establishing a "session".  The communication is assumed to only be in
a single direction (device to session).  As such, the cloud service needs to
ensure that the session establishment packet remains available for as long as
there are session data packets using that session.  For example, with MQTT, the
QoS for the session packet can be set to "at least once" delivery, to ensure the
packet is received, whereas the data payload packets may only need a best effort
delivery guarantee.

The CEDAR Session packet is similar to the full payload above, except that the
session key itself is a key for an AEAD cipher (in this case AES128GCM).  There
is also a new header for a session ID.  The format of the session ID is not
defined by CEDAR, but it is merely required that the session ID be unique for a
given sender.  This could be implemented via a Non-volatile counter on the
device, or by using a larger random number from a properly seeded CPRNG.

The key also should be generated randomly, using a properly seeded CPRNG.

Once the session packet has been sent, further payload can be sent using a CEDAR
session payload packet.  This uses the session key sent via the session packet
to encrypt and authenticate the payload, without the overhead, either of space,
or computation time, of computing a digital signature each time.

## Individual packets

The following sections describe each of the above 3 packet types.

### CEDAR full payload

The full payload represents an encrypted and signed payload.  This is useful for
infrequently sent data where the overhead of setting up a session is not as
useful.

The payload consists of using `COSE_Sign1(COSE_Encrypt(payload))`.  These
packets are described by COSE, with the following specifics:

```
; COSE_Sign1, based off of cose-examples/ecdsa-examples/ecdsa-sig-01.json.
[
    ; Protected header
    <<
        {
            1: -7,
            ; TODO: This is not necessary with the wrappers, keep it?
            3: -65538,
        }
    >>,
    ; Unprotected header
    {
        ; Key ID of sender.
        4: b"O=Linaro, CN=Flow test device",
    },
    ; Payload.  A bstr of the nested COSE_Encrypt payload.
    <<
        ; COSE_Encrypt, based off of cose-examples/ecdh-wrap-examples/p256-wrap-128-01.json
        [
            ; Protected header
            <<
                {
                    ; Algorithm, AES128GCM
                    1: 1,
                }
            >>,
            ; Unprotected header
            {
                ; Nonce.  12 bytes as defined by AES128GCM.
                5: h'5633EA0328B1522B0EFFBBF3',
            },
            ; Ciphertext
            h'31DE2E0CE8F2981B201C16218795E32BDEB663E5783B88FBFBDD295DCC6E40',
            ; Recipients
            [
                ; First (and only recipient)
                [
                    ; Protected header.
                    <<
                        {
                            ; algorithm ECDH-ES + A128KW (see https://www.iana.org/assignments/cose/cose.xhtml)
                            1: -29,
                        }
                    >>,
                    ; Recipient data
                    {
                        ; Recipient key id
                        4: b"O=Linaro, CN=Flow test cloud",
                        ; Ephemeral key
                        -1: {
                            ; kty: 2, as per COSE spec
                            1: 2,
                            ; Key is P256
                            -1: 1,
                            ; x value of ephemeral public key
                            -2: h'82B0F8105315677518A635EBE3466975DF1C1510A4A730356AC44B23AD543E1A',
                            ; y value of ephemeral public key.
                            -3: h'A8066488A92FE03C0F3A4FC4622CBAD44873540B97995E70AB6B7A378BEFBEFD',
                        },
                    },
                    ;  encrypted session key
                    h'E7E8470794B2A5EBD90ABDC8E00F364DF2292C0AFC0A06DC',
                ],
            ],
        ]
    >>,
    ; Payload signature.
    h'762B7F6D39958365E40436DB60766D3DDD60571DAF26FC5095D66DD6FB4FA5D9EA236300A85CBE286585A0221EA9F3C86C74D35E28196DEEDE54E6BC952209FC',
]
```


### CEDAR Session packet

This packet is similar to the full payload packet above, except that the
protected header contains a session ID (should this be protected?), and the
encrypted payload is not a message, but a session key that will be used in
subsequent messages.

```
[
    <<
        {
            1: -7,
            ; TODO: Probably not needed with wrappers.
            3: -65539,
            ; Session ID.
            -65537: h'EECBD8B91F9D6E428F2D9DCD7C42CD43',
        }
    >>,
    {
        4: b"O=Linaro, CN=Flow test device",
    },
    <<
        [
            <<
                {
                    1: 1,
                }
            >>,
            {
                5: h'F825082D6786CC11303646D4',
            },
            h'7D759B930653AF7AA0D61391329D47C5BD0C3B7A928DC09313B647B3A2EA38A3',
            [
                [
                    <<
                        {
                            1: -29,
                        }
                    >>,
                    {
                        4: b"O=Linaro, CN=Flow test cloud",
                        -1: {
                            1: 2,
                            -1: 1,
                            -2: h'C011DB4D446A1B71F995620277657BB5BBA1FD85CC170D83EB85CC560B8BD050',
                            -3: h'8FC7EB550C509078348E9BD11E9C320977FF066398E750979E389A4B18F60030',
                        },
                    },
                    h'41284E2DC31E0FEF42ED3899995A1966F0BF453580B99A7D',
                ],
            ],
        ]
    >>,
    h'EFF0930444BF506E67390EE59AE2C7A2D5DDF94A8074D522F639897938DEFEC83DA4590DDAC53500FB63D62176950D78B0D86561ECCF6809B64A76E8336E62B2',
]
```

### CEDAR Session Payload

Once a session has been established, the following packet can transmit payload
using the session key sent with the session packet.

```
; COSE_Encrypt0, based on cose-examples/aes-gcm-examples/aes-gcm-enc-01.json
[
    ; Protected header
    <<
        {
            ; alg is AES128GCM
            1: 1,
            ; Session ID.
            -65537: h'EECBD8B91F9D6E428F2D9DCD7C42CD43',
        }
    >>,
    ; Unprotected header.
    {
        ; Nonce, 12 bytes per AES128GCM
        5: h'DAB2C7F012D3E61A2D6176DB',
    },
    ; Ciphertext + tag.  The last 16 bytes are the tag used by AES128GCM to
    verify the message.
    h'4BCA73B4CC3DB31FA751CEA79896061AC1B8161E37EFD39AC3F9219694DE28',
]
```
