"""C2000G2 power station device tests.

.. moduleauthor:: kb1ibt

"""

import pytest

from SolixBLE.devices.c2000g2 import C2000G2

########################
# Test device commands #
########################

# These tests are for sending commands to the device and making sure the
# correct calls are made to the command sending functions and errors are
# raised where appropriate. See test_send_command() in test_commands.py.

C2000G2_TEST_COMMANDS = [
    pytest.param(
        C2000G2,
        "_post_connect",
        [],
        [("4100", "a10121")],
        id="c2000g2_post_connect_subscribe",
    ),
    # 4100 is a poll, not a subscription: one request, one reading. Repeating it
    # is what turns it into a steady feed.
    pytest.param(
        C2000G2,
        "_keep_alive",
        [],
        [("4100", "a10121")],
        id="c2000g2_keep_alive_poll",
    ),
    # 4057 is the actual realtime latch. It is only honoured with routing byte
    # 0x21 -- the MQTT-side 0x22 is accepted and silently dropped.
    pytest.param(
        C2000G2,
        "enable_realtime_telemetry",
        [],
        [("4057", "a10121a2020101")],
        id="c2000g2_realtime_enable",
    ),
    pytest.param(
        C2000G2,
        "disable_realtime_telemetry",
        [],
        [("4057", "a10121a2020100")],
        id="c2000g2_realtime_disable",
    ),
    # The Gen 2 has no per-setting opcodes: the display switch, brightness,
    # timeout and both SoC limits are all fields of the 4103 system group,
    # selected by payload tag.
    pytest.param(
        C2000G2,
        "turn_display_on",
        [],
        [("4103", "a10121a2020101")],
        id="c2000g2_display_on",
    ),
    pytest.param(
        C2000G2,
        "turn_display_off",
        [],
        [("4103", "a10121a2020100")],
        id="c2000g2_display_off",
    ),
    pytest.param(
        C2000G2,
        "set_display_brightness",
        [1],
        [("4103", "a10121a3020101")],
        id="c2000g2_brightness_low",
    ),
    pytest.param(
        C2000G2,
        "set_display_brightness",
        [3],
        [("4103", "a10121a3020103")],
        id="c2000g2_brightness_high",
    ),
    pytest.param(
        C2000G2,
        "set_display_brightness",
        [4],
        ValueError,
        id="c2000g2_brightness_invalid",
    ),
    # The timeout is a little-endian u16 under type 02, not a single byte.
    pytest.param(
        C2000G2,
        "set_display_timeout",
        [60],
        [("4103", "a10121a403023c00")],
        id="c2000g2_display_timeout_60",
    ),
    pytest.param(
        C2000G2,
        "set_display_timeout",
        [1800],
        [("4103", "a10121a403020807")],
        id="c2000g2_display_timeout_1800",
    ),
    pytest.param(
        C2000G2,
        "set_display_timeout",
        [90],
        ValueError,
        id="c2000g2_display_timeout_invalid",
    ),
    # The app only offers 80/85/90/95/100 and 1/5/10/15/20, but the firmware
    # accepts any percentage -- 99 was set over BLE and read back verbatim.
    pytest.param(
        C2000G2,
        "set_max_battery_percentage",
        [100],
        [("4103", "a10121aa020164")],
        id="c2000g2_max_soc_100",
    ),
    pytest.param(
        C2000G2,
        "set_max_battery_percentage",
        [99],
        [("4103", "a10121aa020163")],
        id="c2000g2_max_soc_off_menu",
    ),
    pytest.param(
        C2000G2,
        "set_max_battery_percentage",
        [101],
        ValueError,
        id="c2000g2_max_soc_invalid",
    ),
    pytest.param(
        C2000G2,
        "set_min_battery_percentage",
        [5],
        [("4103", "a10121ab020105")],
        id="c2000g2_min_soc_5",
    ),
    pytest.param(
        C2000G2,
        "set_min_battery_percentage",
        [-1],
        ValueError,
        id="c2000g2_min_soc_invalid",
    ),
    # The output countdowns are a u32 under type 03 -- the same 4-byte form the
    # `fe` timestamp uses -- not the u16 the display timeout takes.
    pytest.param(
        C2000G2,
        "set_ac_output_timeout",
        [300],
        [("4101", "a10121a305032c010000")],
        id="c2000g2_ac_timeout",
    ),
    pytest.param(
        C2000G2,
        "set_dc_output_timeout",
        [600],
        [("4102", "a10121a3050358020000")],
        id="c2000g2_dc_timeout",
    ),
    pytest.param(
        C2000G2,
        "set_ac_output_timeout",
        [0],
        [("4101", "a10121a3050300000000")],
        id="c2000g2_ac_timeout_disable",
    ),
    pytest.param(
        C2000G2,
        "set_ac_output_timeout",
        [450],
        ValueError,
        id="c2000g2_ac_timeout_bad_step",
    ),
    pytest.param(
        C2000G2,
        "set_dc_output_timeout",
        [86700],
        ValueError,
        id="c2000g2_dc_timeout_out_of_range",
    ),
    # Inherited from the C1000 G2 unchanged -- the AC and DC output switches use
    # the same opcodes and payload on both models.
    pytest.param(
        C2000G2,
        "turn_ac_on",
        [],
        [("4101", "a10121a2020101")],
        id="c2000g2_ac_on",
    ),
    pytest.param(
        C2000G2,
        "turn_dc_off",
        [],
        [("4102", "a10121a2020100")],
        id="c2000g2_dc_off",
    ),
]
