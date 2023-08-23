import sys, getopt, struct

HELP_MESSAGE = """log2csv
Usage: log2csv.py -i <input> -o <output>

Input file: Binary log file
Output file: CSV file containing human-readable log data

Options:
-d | --debug    Print debug info
-h | --help     Print this message
-i | --ifile    Binary log file to read
-o | --ofile    File to store the CSV data
"""

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
    debug(f"{IDENTIFIERS[packet_id]}")

    time = timestamp / TICKS_IN_1S
    if time < 15.0:
        debug(" @ {:2.4f}s\n".format(time))
    else:
        debug(f" ERR: TIME ERROR: ")
        debug("{:2.4f}\ns".format(time))

    for i, b in enumerate(flags):
        debug("{0:x}".format(b))
    debug("\n")

    if signals is not None:
        debug("  {:.3f}\n".format(signals[0]))
        debug("  {:.3f}\n".format(signals[1]))
        debug("  {:.3f}\n".format(signals[2]))
        debug("  {:.3f}\n".format(signals[3]))
        debug("  {:.3f}\n".format(signals[4]))
        debug("  {:.3f}\n".format(signals[5]))
        debug("  {:.3f}\n".format(signals[6]))
        debug("  {:.3f}\n".format(signals[7]))
        debug("  {:.3f}\n".format(signals[8]))
        debug("  {:.3f}\n".format(signals[9]))
        debug("  {:.3f}\n".format(signals[10]))
        debug("  {:.3f}\n".format(signals[11]))
        debug("  0b{0:b}\n".format(signals[12]))

def print_to_csv(out_file, packet_id, timestamp, flags, signals) -> None:

    print(f"{IDENTIFIERS[packet_id]},", end="")
    print(f"{timestamp},", end="")
    # TODO flags
    print(f"{signals[0]},", end="")
    print(f"{signals[1]},", end="")
    print(f"{signals[2]},", end="")
    print(f"{signals[3]},", end="")
    print(f"{signals[4]},", end="")
    print(f"{signals[5]},", end="")
    print(f"{signals[6]},", end="")
    print(f"{signals[7]},", end="")
    print(f"{signals[8]},", end="")
    print(f"{signals[9]},", end="")
    print(f"{signals[10]},", end="")
    print(f"{signals[11]},", end="")
    print(f"{int(signals[12] & 0b1 == 0b1)},", end="")
    print(f"{int(signals[12] & 0b10 == 0b10)},", end="")
    print(f"{int(signals[12] & 0b100 == 0b100)},", end="")
    print("")

def parse_input_args(argv) -> (str, str):
    global g_debug_mode
    input_file = ""
    output_file = ""

    opts, args, = getopt.getopt(argv, "dhi:o:", ["debug", "ifile", "ofile"])

    for opt, arg in opts:
        if opt in ("-d", "--debug"):
            g_debug_mode = True
        elif opt == "-h":
            die(HELP_MESSAGE)
        elif opt in ("-i", "--ifile"):
            input_file = arg
        elif opt in ("-o", "--ofile"):
            output_file = arg

    if input_file == "":
        die(HELP_MESSAGE)
    if output_file == "":
        output_file = "./output.csv"

    return input_file, output_file

def main(argv):
    in_file, out_file = parse_input_args(argv)

    with open(in_file, "rb") as file:
        logfile_bytes = file.read()

    i = 0
    while i < len(logfile_bytes):
        packet_id = bytes(logfile_bytes[i:i+4])
        if packet_id not in [PKTID_MOTOR]:
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
            signal_size = struct.unpack(BYTE_FORMAT, signal_size_bytes)[0]
            j += 1

            nsignals = int.from_bytes(signal_size_bytes)
            if nsignals != 49:
                debug(f"ERR: {IDENTIFIERS[packet_id]}: SIGSZ: act({nsignals}) != exp(49) at i {hex(j)}\n")
                i += 1
                continue

            # unpack flags
            signal_data_bytes = logfile_bytes[j:j+49]
            signals = struct.unpack(MOTOR_SIGNAL_STRUCT_FORMAT, signal_data_bytes)
            j += nsignals

        print_debug_info(packet_id, timestamp, flags, signals)
        
        print_to_csv(out_file, packet_id, timestamp, flags, signals)

        # update i
        i = j

if __name__ == "__main__":
    main(sys.argv[1:])

