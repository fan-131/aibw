import time
import random
import logging
from queue import Queue
from scapy.all import sniff, send, IP, TCP, Raw


logging.basicConfig(
    level=logging.INFO,
    format='',
    datefmt=''
)
class WatermarkEmbedder:
    def __init__(self, watermark_bits='1010110100', window_size=0.9, queue_length=4, redundancy=1):
        self.watermark = watermark_bits
        self.l = len(watermark_bits)
        self.r = redundancy
        self.n = self.l * self.r
        self.T = window_size
        self.offset = 0.2T
        self.queue = Queue(maxsize=queue_length)
        self.max_queue_length = queue_length

        self.D0_values = {
            3: 0.00,
            4: 0.03,
            5: 0.06,
            6: 0.09,
            7: 0.1,
        }

        self.reset()

    def get_delay(count):
        base_delay = 0.03  
        delay = base_delay * (count - 3)  
        if delay < 0:
            delay = 0
        return min(delay, 0.1)

    def reset(self):
        self.is_complete = False
        self.stop_sniff_flag = False
        self.start_ts = -1.0
        self.prev_ts = -1.0
        self.relative_time = 0.0
        self.packet_counter = 0

        self.index_pbit = 0
        self.count1 = 0
        self.count0 = 0

    def stop_filter(self, pkt):
        return self.stop_sniff_flag

    def detect_stop(self, pkt):
        if Raw in pkt and b'hello' in pkt[Raw].load:
            logging.info("Detected 'hello' — stopping sniff")
            self.stop_sniff_flag = True

    def packet_callback(self, pkt):
        self.packet_counter += 1
        self.detect_stop(pkt)

        now = time.perf_counter()
        if self.prev_ts > 0:
            self.relative_time += now - self.prev_ts
        else:
            self.start_ts = now

        self.prev_ts = now
        logging.info(f"Packet received (#{self.packet_counter})")

        self.embed(pkt, self.relative_time)

    def embed(self, pkt, tc):
        if self.is_complete:
            self.forward(pkt)
            return

        if tc < self.offset:
            return

        offset_time = tc - self.offset
        if int(offset_time / self.T) >= self.n:
            self.is_complete = True
            logging.info("Watermark embedding complete.")
            self.forward(pkt)
            return

        index_bit = int(offset_time / self.T)
        current_bit = self.watermark[index_bit]

        if current_bit == '1':
            self._embed_one(pkt, index_bit)
        else:
            self._embed_zero(pkt, index_bit, tc)

    def _embed_one(self, pkt, index_bit):
        if index_bit == self.index_pbit:
            self.count1 += 1
            if 3 <= self.count1 <= 6:
                self.queue.put(pkt)
                if self.queue.full():
                    while not self.queue.empty():
                        self.forward(self.queue.get())
            else:
                self.forward(pkt)
        else:
            self.index_pbit = index_bit
            self.count1 = 1
            self.forward(pkt)

    def _embed_zero(self, pkt, index_bit, tc):
        if index_bit == self.index_pbit:
            self.count0 += 1
            delay = self.D0_values.get(self.count0, 0)
            remaining_time = tc + delay - (time.perf_counter() - self.start_ts)
            if remaining_time > 0:
                time.sleep(remaining_time)
            self.forward(pkt)
        else:
            self.index_pbit = index_bit
            self.count0 = 1
            self.forward(pkt)

    def forward(self, pkt):
        tcp_payload = pkt[TCP].payload
        spoofed_packet = IP(src="", dst="") / TCP(dport=) / Raw(load=tcp_payload)

        send(spoofed_packet, verbose=False)
        logging.info("Packet forwarded.")


    def start_sniffing(self, iface=None, filter_exp=''):
        sniff(prn=self.packet_callback, stop_filter=self.stop_filter, filter=filter_exp, iface=iface)


# ================== 主运行逻辑 ==================
if __name__ == "__main__":
    embedder = WatermarkEmbedder()

    for i in range(100):
        logging.info(f"==== Sniffing Round {i + 1} ====")
        embedder.reset()
        embedder.start_sniffing()
        logging.info("Sniffing complete. Sleeping...")
        time.sleep(5)
