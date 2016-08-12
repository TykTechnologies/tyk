import coprocess_session_state_pb2 as session_state_pb

#class TykSession:
#    def __init__(self, session):
#        self.object = session

TykSession = session_state_pb.SessionState
AccessSpec = session_state_pb.AccessSpec
AccessDefinition = session_state_pb.AccessDefinition
BasicAuthData = session_state_pb.BasicAuthData
JWTData = session_state_pb.JWTData
Monitor = session_state_pb.Monitor
