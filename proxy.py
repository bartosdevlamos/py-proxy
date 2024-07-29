import asyncio
import argparse
from joblib import dump, load
from sklearn.ensemble import IsolationForest
import numpy as np
import logging

logging.basicConfig(level=logging.INFO)

class ProxyServer:
    def __init__(self, local_port, remote_ip, remote_port, model=None):
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.model = model
        self.learn_mode = False
        self.legitimate_traffic = []
        self.max_learn_requests = 10000

    async def handle_tcp(self, reader, writer):
        peername = writer.get_extra_info('peername')
        logging.info(f"TCP Connection from {peername}")

        if self.model and not self.learn_mode:
            if not self.is_legitimate(peername):
                logging.warning(f"Blocked malicious TCP traffic from {peername}")
                writer.close()
                await writer.wait_closed()
                return
        
        remote_reader, remote_writer = await asyncio.open_connection(self.remote_ip, self.remote_port)
        
        async def forward(reader, writer):
            try:
                while not reader.at_eof():
                    data = await reader.read(1024)
                    if self.learn_mode:
                        self.legitimate_traffic.append(self.extract_features(data))
                        if len(self.legitimate_traffic) >= self.max_learn_requests:
                            self.train_model()
                    writer.write(data)
                    await writer.drain()
            except Exception as e:
                logging.error(f"Error in forward: {e}")
            finally:
                writer.close()
                await writer.wait_closed()

        await asyncio.gather(forward(reader, remote_writer), forward(remote_reader, writer))

    async def handle_udp(self, data, addr):
        logging.info(f"UDP Packet from {addr}")

        if self.model and not self.learn_mode:
            if not self.is_legitimate(addr):
                logging.warning(f"Blocked malicious UDP traffic from {addr}")
                return

        if self.learn_mode:
            self.legitimate_traffic.append(self.extract_features(data))
            if len(self.legitimate_traffic) >= self.max_learn_requests:
                self.train_model()

        remote_transport, _ = await loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), remote_addr=(self.remote_ip, self.remote_port))
        remote_transport.sendto(data)
        remote_transport.close()

    def is_legitimate(self, data):
        features = self.extract_features(data)
        prediction = self.model.predict([features])
        return prediction == 1

    def extract_features(self, data):
        # Simple feature extraction for demonstration purposes
        return [len(data)]

    def save_model(self, filepath):
        dump(self.model, filepath)

    def load_model(self, filepath):
        self.model = load(filepath)

    def train_model(self):
        logging.info("Training model with collected traffic data.")
        self.model = IsolationForest(contamination=0.1)
        self.model.fit(self.legitimate_traffic)
        self.save_model(args.model_file)
        self.learn_mode = False
        logging.info("Model trained and saved successfully.")

    async def start(self):
        server = await asyncio.start_server(self.handle_tcp, '0.0.0.0', self.local_port)
        await server.serve_forever()

async def start_udp_proxy(proxy, local_port):
    await loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), local_addr=('0.0.0.0', local_port))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Proxy Server with Machine Learning')
    parser.add_argument('--learn', action='store_true', help='Enable learning mode')
    parser.add_argument('--tcp_port', type=int, default=27015, help='Local TCP port to listen on')
    parser.add_argument('--udp_port', type=int, default=27005, help='Local UDP port to listen on')
    parser.add_argument('--remote_ip', type=str, required=True, help='Remote IP to forward traffic to')
    parser.add_argument('--remote_tcp_port', type=int, default=28282, help='Remote TCP port to forward traffic to')
    parser.add_argument('--remote_udp_port', type=int, default=28285, help='Remote UDP port to forward traffic to')
    parser.add_argument('--model_file', type=str, default='model.joblib', help='Path to save/load the model')

    args = parser.parse_args()
    
    proxy = ProxyServer(args.tcp_port, args.remote_ip, args.remote_tcp_port)
    
    if args.learn:
        proxy.learn_mode = True
    else:
        try:
            proxy.load_model(args.model_file)
        except FileNotFoundError:
            logging.warning("Model file not found, running without model")

    loop = asyncio.get_event_loop()
    loop.create_task(proxy.start())
    loop.create_task(start_udp_proxy(proxy, args.udp_port))
    loop.run_forever()
