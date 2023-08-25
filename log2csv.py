import sys, getopt, struct

HELP_MESSAGE = """log2csv
Usage: log2csv.py -i <input> -o <output>

Input file: Binary log file
Output file: CSV file containing human-readable log data

Options:
  -d    Print debug info
  -h    Print this message
  -i    Binary log file to read
  -o    File to store the CSV data
"""

CSV_HEADER_STR = "Packet Type,Timestamp,Fault Flags,Filtered High Voltage,Command Vd,Command Vq,Measured Id,Measured Iq,Idq Negative Sequence,Idq Positive Sequence,I Zero Sequence,Back EMF,Estimated Torque,Torque Command,Shaft Speed,Open Loop Startup,Open Loop Fail,Speed Control Enabled,\n"

TICKS_IN_1S = 75000000.0

PACKET_ID_FORMAT = ">I"
TIMESTAMP_FORMAT = ">Q"
BYTE_FORMAT = ">B"
MOTOR_SIGNAL_STRUCT_FORMAT = ">ffffffffffffB"
MOTOR_SIGNAL_SIZE = 49

PKTID_MOTOR = b"\xcc\xcc\xcc\xcc"
PKTID_FAULT = b"\xaa\xaa\xaa\xaa"
PKTID_PWRON = b"\x99\x99\x99\x99"
PKTID_PWROF = b"\x66\x66\x66\x66"

IDENTIFIERS = {
    PKTID_MOTOR : "MOTOR PACKET",
    PKTID_FAULT : "FAULT PACKET",
    PKTID_PWRON : "POWER ON PACKET",
    PKTID_PWROF : "POWER OFF PACKET",
}

g_debug_mode = False

def die(msg, errno=0) -> None:
    print(msg, end="")
    sys.exit(errno)

def debug(msg: str) -> None:
    global g_debug_mode
    if g_debug_mode:
        print(msg, end="")

def print_debug_info(packet_id: str, timestamp: int, flags: bytes, signals: tuple) -> None:
    debug("----------------------------------------\n")

    debug(f"Packet Type: {IDENTIFIERS[packet_id]}")

    time = timestamp / TICKS_IN_1S
    if time < 15.0:
        debug("Timestamp: ")
        debug("{:2.4f}s\n".format(time))
    else:
        debug(f" ERR: TIME ERROR: ")
        debug("{:2.4f}\ns".format(time))

    debug(f"Fault Flags (hex): ")
    for i, b in enumerate(flags):
        debug("{0:x}".format(b))
    debug("\n")

    if signals is not None:
        debug("Filtered High Voltage: ")
        debug("{:.3f}".format(signals[0]))
        debug("\nCommand Vd: ")
        debug("{:.3f}".format(signals[1]))
        debug("\nCommand Vq: ")
        debug("{:.3f}".format(signals[2]))
        debug("\nMeasured Id: ")
        debug("{:.3f}".format(signals[3]))
        debug("\nMeasured Iq: ")
        debug("{:.3f}".format(signals[4]))
        debug("\nIdq Negative Sequence: ")
        debug("{:.3f}".format(signals[5]))
        debug("\nIdq Positive Sequence: ")
        debug("{:.3f}".format(signals[6]))
        debug("\nI Zero Sequence: ")
        debug("{:.3f}".format(signals[7]))
        debug("\nBack EMF: ")
        debug("{:.3f}".format(signals[8]))
        debug("\nTorque Command: ")
        debug("{:.3f}".format(signals[9]))
        debug("\nShaft Speed: ")
        debug("{:.3f}".format(signals[10]))
        debug("\nSpeed Controller Torque Command: ")
        debug("{:.3f}".format(signals[11]))
        debug("\nOpen Loop Startup: ")
        debug(signals[12] & 0b100 == 0b100)
        debug("\nOpen Loop Fail: ")
        debug(signals[12] & 0b010 == 0b010)
        debug("\nSpeed Control Enabled: ")
        debug(signals[12] & 0b001 == 0b001)
        debug("\n")

def csv_write_header(out_file) -> None:
    out_file.write(CSV_HEADER_STR)

def csv_write_entry(out_file, packet_id, timestamp, flags, signals) -> None:
    w = out_file.write

    w(f"{IDENTIFIERS[packet_id]},")
    w(f"{timestamp},")

    for i, b in enumerate(flags):
        w("{0:x}".format(b))
    w(",")

    if signals is not None:
        w(f"{signals[0]},")
        w(f"{signals[1]},")
        w(f"{signals[2]},")
        w(f"{signals[3]},")
        w(f"{signals[4]},")
        w(f"{signals[5]},")
        w(f"{signals[6]},")
        w(f"{signals[7]},")
        w(f"{signals[8]},")
        w(f"{signals[9]},")
        w(f"{signals[10]},")
        w(f"{signals[11]},")
        w(f"{int(signals[12] & 0b1 == 0b1)},")
        w(f"{int(signals[12] & 0b10 == 0b10)},")
        w(f"{int(signals[12] & 0b100 == 0b100)},")

    w("\n")


def parse_input_args(argv) -> (str, str):
    global g_debug_mode
    input_file = ""
    output_file = ""

    opts, args, = getopt.getopt(argv, "dhi:o:")

    for opt, arg in opts:
        if opt == "-d":
            g_debug_mode = True
        elif opt == "-h":
            die(HELP_MESSAGE)
        elif opt == "-i":
            input_file = arg
        elif opt == "-o":
            output_file = arg

    if input_file == "":
        die(HELP_MESSAGE)
    if output_file == "":
        output_file = "./output.csv"

    return input_file, output_file

def main(argv):
    in_path, out_path = parse_input_args(argv)

    with open(in_path, "rb") as file:
        logfile_bytes = file.read()
    
    out_file = open(out_path, "w")
    csv_write_header(out_file)

    i = 0
    while i < len(logfile_bytes):
        packet_id = bytes(logfile_bytes[i:i+4])
        if packet_id not in IDENTIFIERS.keys():
            i += 1
            continue
        j = i + 4

        # unpack timestamp
        timestamp_bytes = logfile_bytes[j:j+8]
        timestamp = struct.unpack(TIMESTAMP_FORMAT, timestamp_bytes)[0]
        j += 8

        # unpack sizeof flags
        flag_size_bytes = logfile_bytes[j:j+1]
        nflags = struct.unpack(BYTE_FORMAT, flag_size_bytes)[0]
        j += 1

        # check if size match
        if nflags != 21:
            debug(f"ERR: {IDENTIFIERS[packet_id]}: FLGSZ: act({nflags}) != exp(21) at {hex(j)}\n")
            i += 1
            continue

        # unpack flags
        flags = logfile_bytes[j:j+nflags]
        j += nflags

        signals = None
        if packet_id == PKTID_MOTOR:
            # unpack sizeof signals
            signal_size_bytes = logfile_bytes[j:j+1]
            nsignals = struct.unpack(BYTE_FORMAT, signal_size_bytes)[0]
            j += 1

            if nsignals != 49:
                debug(f"ERR: {IDENTIFIERS[packet_id]}: SIGSZ: act({nsignals}) != exp(49) at i {hex(j)}\n")
                i += 1
                continue

            # unpack flags
            signal_data_bytes = logfile_bytes[j:j+49]
            signals = struct.unpack(MOTOR_SIGNAL_STRUCT_FORMAT, signal_data_bytes)
            j += nsignals

        print_debug_info(packet_id, timestamp, flags, signals)
        
        csv_write_entry(out_file, packet_id, timestamp, flags, signals)

        # update i
        i = j

    out_file.close()

if __name__ == "__main__":
    main(sys.argv[1:])
