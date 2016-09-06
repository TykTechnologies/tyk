import coprocess_object_pb2
from coprocess_session_state_pb2 import SessionState

import grpc, time, json

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

from concurrent import futures

def MyPreMiddleware(coprocess_object):
  coprocess_object.request.set_headers["myheader"] = "myvalue"
  return coprocess_object

def MyPostMiddleware(coprocess_object):
  coprocess_object.request.set_headers["anotherheader"] = "anothervalue"
  return coprocess_object

def MyAuthCheck(coprocess_object):
  valid_token = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
  request_token = coprocess_object.request.headers["Authorization"]

  if request_token == valid_token:
      new_session = SessionState()
      new_session.rate = 1000.0
      new_session.per = 1.0
      coprocess_object.metadata["token"] = "mytoken"
      coprocess_object.session.CopyFrom(new_session)

  else:
      coprocess_object.request.return_overrides.response_code = 401
      coprocess_object.request.return_overrides.response_error = 'Not authorized (Python middleware)'

  return coprocess_object

class MyDispatcher(coprocess_object_pb2.DispatcherServicer):
  def Dispatch(self, coprocess_object, context):
    if coprocess_object.hook_name == "MyPreMiddleware":
        coprocess_object = MyPreMiddleware(coprocess_object)

    if coprocess_object.hook_name == "MyPostMiddleware":
        coprocess_object = MyPostMiddleware(coprocess_object)

    if coprocess_object.hook_name == "MyAuthCheck":
        coprocess_object = MyAuthCheck(coprocess_object)

    return coprocess_object

  def DispatchEvent(self, event_wrapper, context):
    event = json.loads(event_wrapper.payload)
    return coprocess_object_pb2.EventReply()


def serve():
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
  coprocess_object_pb2.add_DispatcherServicer_to_server(
      MyDispatcher(), server)
  server.add_insecure_port('[::]:5555')
  server.start()
  try:
    while True:
      time.sleep(_ONE_DAY_IN_SECONDS)
  except KeyboardInterrupt:
    server.stop(0)

if __name__ == '__main__':
  serve()
