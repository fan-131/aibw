import numpy as np

from scapy.all import *
import time
import numpy as np
import logging
from scapy.all import sniff, Raw


logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class WatermarkDetector:
    def __init__(self, watermark='1010110100', window_size=0.9, redundancy=1):
        self.watermark = watermark
        self.l = len(watermark)
        self.r = redundancy
        self.n = self.l * self.r
        self.T = window_size

        self.reset()

    def reset(self):
        self.is_complete = False
        self.stop_sniff = False

        self.beginning_ts = -1.0
        self.time_counter = 0.0
        self.previous_ts = -1.0

        self.watermarklist = []
        self.ipdtime = np.zeros()

        self.offset = 0
        self.row = 0
        self.line = 0
        self.index_pintervals = 0
        self.count = 0

        logging.debug("Detector state has been reset.")

    def packet_stops(self, packet):
        if Raw in packet and b'hello' in packet[Raw].load:
            self.stop_sniff = True
            logging.info("Termination packet containing 'hello' detected. Stopping capture.")

    def cbk_processing(self, pkt):
        if self.is_complete:
            self.stop_sniff = True
            return

        self.packet_stops(pkt)

        now = time.perf_counter()
        if self.previous_ts > 0:
            self.time_counter += now - self.previous_ts
        else:
            self.beginning_ts = now
            logging.debug("First packet timestamp initialized.")

        self.previous_ts = now

        self.processing(pkt, self.time_counter)

    def processing(self, pkt, tc):
        if self.is_complete:
            return

        if tc < self.offset:
            return

        offset_time = tc - self.offset
        if int(offset_time / self.T) >= self.n:
            self.is_complete = True
            logging.info("All watermark intervals received. Commencing watermark decoding.")

            zero_indices = np.argmax(self.ipdtime == 0, axis=1)
            for row_idx, zero_idx in enumerate(zero_indices):
                elements_before_zero = self.ipdtime[row_idx, :zero_idx]
                differences = np.diff(elements_before_zero)
                diff_size = differences.size

                if diff_size > 2:
                    count1 = np.sum(differences < 0.1)
                    count2 = np.sum(differences >= 0.12)
                    bit = 1 if count1 >= count2 else 0
                    self.watermarklist.append(bit)
                elif diff_size == 0:
                    self.watermarklist.append(0)
                elif diff_size == 1:
                    bit = 0 if differences[0] > 0.12 else 1
                    self.watermarklist.append(bit)
                elif diff_size == 2:
                    diff_0 = abs(differences[0] - 0.11)
                    diff_1 = abs(differences[1] - 0.11)
                    if diff_0 < diff_1:
                        bit = 0 if differences[0] > 0.12 else 1
                    else:
                        bit = 0 if differences[1] < 0.1 else 1
                    self.watermarklist.append(bit)

            H = sum(el != int(ch) for el, ch in zip(self.watermarklist, self.watermark))
            if H > 2:
                logging.warning(f"Decoded watermark differs significantly from the original. Hamming Distance: {H}")
                logging.debug(f"Decoded bits: {self.watermarklist}")
                logging.debug(f"Original watermark: {self.watermark}")
            else:
                logging.info(f"Watermark decoded successfully with acceptable Hamming Distance: {H}")
                logging.debug(f"Decoded bits: {self.watermarklist}")

            self.stop_sniff = True
        else:
            index_intervals = int(offset_time / self.T)
            if index_intervals == self.index_pintervals:
                self.count += 1
                if 3 <= self.count <= 6:
                    self.ipdtime[self.row, self.line] = round(self.previous_ts, 6)
                    self.line += 1
                    logging.debug(f"Recorded timestamp at ipdtime[{self.row}, {self.line-1}]: {self.previous_ts:.6f}")
            else:
                self.row += 1
                self.line = 0
                self.count = 1
                logging.debug(f"Moving to next row {self.row} for interval recording.")
            self.index_pintervals = index_intervals

    def stop_sniffing(self, pkt):
        return self.stop_sniff

def main():
    detector = WatermarkDetector()

    for i in range(100):
        logging.info(f"Starting sniffing cycle {i+1}/100.")
        detector.reset()
        sniff(filter='',
              prn=detector.cbk_processing,
              stop_filter=detector.stop_sniffing)
        logging.info(f"Completed sniffing cycle {i+1}, entering cooldown period.")
        time.sleep(5)

if __name__ == '__main__':
    main()

