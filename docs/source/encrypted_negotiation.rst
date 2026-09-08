=================================
Encrypted negotiation and pairing
=================================

.. _BLEDevice: https://bleak.readthedocs.io/en/latest/api/index.html#bleak.backends.device.BLEDevice/


Some Anker devices negotiate their session over an encrypted handshake rather
than the cleartext one, and some firmware additionally requires the client to
be *paired* to the device -- confirmed by a physical button press -- before it
will stream telemetry or accept commands. Newer firmware in particular enforces
this. Both are handled automatically once the device is told which path to use
and given a stable client token.


Choosing the negotiation path
-----------------------------

Each device advertises a capability byte that says whether it accepts the
encrypted negotiation, readable at scan time before connecting. Read it from the
manufacturer record in the advertisement and pass it to the device when you
construct it; the correct path is then chosen automatically -- encrypted when
the capability's ECDH bit is set, cleartext otherwise::

    from SolixBLE.advertisement import capability_from_advertisement

    capability = capability_from_advertisement(advertising_data)
    device = C1000G2(ble_device, capability=capability)

.. note::

    A `BLEDevice`_ cannot carry the capability itself, so it is passed to the
    constructor rather than attached to the device. When it is not supplied the
    class default is used. The ``advertising_data`` comes from your own Bleak
    scan (for example a Home Assistant Bluetooth callback); the capability is a
    property of the device model and does not change once a unit is bound.


Pairing with a client token
---------------------------

On the encrypted path the device authorizes a specific *client*, identified by a
token you provide. Pass a stable value and **persist it**, so the same client is
recognised on every later connection::

    device = C1000G2(ble_device, capability=capability, client_token=my_token)

If you do not pass one a random token is generated, which means a new client on
every run. On firmware that enforces pairing, the **first** connection with a
new token needs a one-time physical confirmation:

#. Call :py:meth:`.connect`. The device reports that it is awaiting confirmation.
#. Press the button on the device (the same one used to wake its Bluetooth).
#. The connection completes and telemetry begins.

After that first pairing the token is remembered, and every later connection is
authorized immediately with no button press. The whole process is local -- no
Anker account or cloud service is involved.

.. note::

    A device that does not enforce pairing authorizes as soon as the handshake
    completes, so no button press is needed; the token is still registered for
    later connections.
