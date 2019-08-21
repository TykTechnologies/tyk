from concurrent import futures
import grpc
import time

import coprocess_object_pb2_grpc as coprocess
from coprocess_object_pb2 import Object

class Dispatcher(coprocess.DispatcherServicer):
  def Dispatch(self, request, context):
    print('Dispatch is called')
    object = Object()
    return object

  def DispatchEvent(self, request, context):
    print('Dispatch is called')
    object = Object()
    return object

server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
coprocess.add_DispatcherServicer_to_server(Dispatcher(), server)
print('Starting server')
server.add_insecure_port('127.0.0.1:5000')
server.start()

try:
  while True:
    time.sleep(86400)
except KeyboardInterrupt:
  print('Stopping server')
