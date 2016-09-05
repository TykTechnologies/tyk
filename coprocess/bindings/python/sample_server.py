import coprocess_object_pb2

import grpc, time

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

from concurrent import futures

class DispatcherServicer(coprocess_object_pb2.DispatcherServicer):
  def Dispatch(self, request, context):
    print("dispatch", self, request, context)
    return request


def serve():
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
  coprocess_object_pb2.add_DispatcherServicer_to_server(
      DispatcherServicer(), server)
  server.add_insecure_port('[::]:5555')
  server.start()
  try:
    while True:
      time.sleep(_ONE_DAY_IN_SECONDS)
  except KeyboardInterrupt:
    server.stop(0)

if __name__ == '__main__':
  serve()
