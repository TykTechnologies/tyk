package coprocess;

import static io.grpc.stub.ClientCalls.asyncUnaryCall;
import static io.grpc.stub.ClientCalls.asyncServerStreamingCall;
import static io.grpc.stub.ClientCalls.asyncClientStreamingCall;
import static io.grpc.stub.ClientCalls.asyncBidiStreamingCall;
import static io.grpc.stub.ClientCalls.blockingUnaryCall;
import static io.grpc.stub.ClientCalls.blockingServerStreamingCall;
import static io.grpc.stub.ClientCalls.futureUnaryCall;
import static io.grpc.MethodDescriptor.generateFullMethodName;
import static io.grpc.stub.ServerCalls.asyncUnaryCall;
import static io.grpc.stub.ServerCalls.asyncServerStreamingCall;
import static io.grpc.stub.ServerCalls.asyncClientStreamingCall;
import static io.grpc.stub.ServerCalls.asyncBidiStreamingCall;
import static io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall;
import static io.grpc.stub.ServerCalls.asyncUnimplementedStreamingCall;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.0.3)",
    comments = "Source: coprocess_object.proto")
public class DispatcherGrpc {

  private DispatcherGrpc() {}

  public static final String SERVICE_NAME = "coprocess.Dispatcher";

  // Static method descriptors that strictly reflect the proto.
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<coprocess.CoprocessObject.Object,
      coprocess.CoprocessObject.Object> METHOD_DISPATCH =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.UNARY,
          generateFullMethodName(
              "coprocess.Dispatcher", "Dispatch"),
          io.grpc.protobuf.ProtoUtils.marshaller(coprocess.CoprocessObject.Object.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(coprocess.CoprocessObject.Object.getDefaultInstance()));
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<coprocess.CoprocessObject.Event,
      coprocess.CoprocessObject.EventReply> METHOD_DISPATCH_EVENT =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.UNARY,
          generateFullMethodName(
              "coprocess.Dispatcher", "DispatchEvent"),
          io.grpc.protobuf.ProtoUtils.marshaller(coprocess.CoprocessObject.Event.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(coprocess.CoprocessObject.EventReply.getDefaultInstance()));

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static DispatcherStub newStub(io.grpc.Channel channel) {
    return new DispatcherStub(channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static DispatcherBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    return new DispatcherBlockingStub(channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary and streaming output calls on the service
   */
  public static DispatcherFutureStub newFutureStub(
      io.grpc.Channel channel) {
    return new DispatcherFutureStub(channel);
  }

  /**
   */
  public static abstract class DispatcherImplBase implements io.grpc.BindableService {

    /**
     */
    public void dispatch(coprocess.CoprocessObject.Object request,
        io.grpc.stub.StreamObserver<coprocess.CoprocessObject.Object> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_DISPATCH, responseObserver);
    }

    /**
     */
    public void dispatchEvent(coprocess.CoprocessObject.Event request,
        io.grpc.stub.StreamObserver<coprocess.CoprocessObject.EventReply> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_DISPATCH_EVENT, responseObserver);
    }

    @java.lang.Override public io.grpc.ServerServiceDefinition bindService() {
      return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
          .addMethod(
            METHOD_DISPATCH,
            asyncUnaryCall(
              new MethodHandlers<
                coprocess.CoprocessObject.Object,
                coprocess.CoprocessObject.Object>(
                  this, METHODID_DISPATCH)))
          .addMethod(
            METHOD_DISPATCH_EVENT,
            asyncUnaryCall(
              new MethodHandlers<
                coprocess.CoprocessObject.Event,
                coprocess.CoprocessObject.EventReply>(
                  this, METHODID_DISPATCH_EVENT)))
          .build();
    }
  }

  /**
   */
  public static final class DispatcherStub extends io.grpc.stub.AbstractStub<DispatcherStub> {
    private DispatcherStub(io.grpc.Channel channel) {
      super(channel);
    }

    private DispatcherStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected DispatcherStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new DispatcherStub(channel, callOptions);
    }

    /**
     */
    public void dispatch(coprocess.CoprocessObject.Object request,
        io.grpc.stub.StreamObserver<coprocess.CoprocessObject.Object> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_DISPATCH, getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void dispatchEvent(coprocess.CoprocessObject.Event request,
        io.grpc.stub.StreamObserver<coprocess.CoprocessObject.EventReply> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_DISPATCH_EVENT, getCallOptions()), request, responseObserver);
    }
  }

  /**
   */
  public static final class DispatcherBlockingStub extends io.grpc.stub.AbstractStub<DispatcherBlockingStub> {
    private DispatcherBlockingStub(io.grpc.Channel channel) {
      super(channel);
    }

    private DispatcherBlockingStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected DispatcherBlockingStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new DispatcherBlockingStub(channel, callOptions);
    }

    /**
     */
    public coprocess.CoprocessObject.Object dispatch(coprocess.CoprocessObject.Object request) {
      return blockingUnaryCall(
          getChannel(), METHOD_DISPATCH, getCallOptions(), request);
    }

    /**
     */
    public coprocess.CoprocessObject.EventReply dispatchEvent(coprocess.CoprocessObject.Event request) {
      return blockingUnaryCall(
          getChannel(), METHOD_DISPATCH_EVENT, getCallOptions(), request);
    }
  }

  /**
   */
  public static final class DispatcherFutureStub extends io.grpc.stub.AbstractStub<DispatcherFutureStub> {
    private DispatcherFutureStub(io.grpc.Channel channel) {
      super(channel);
    }

    private DispatcherFutureStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected DispatcherFutureStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new DispatcherFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<coprocess.CoprocessObject.Object> dispatch(
        coprocess.CoprocessObject.Object request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_DISPATCH, getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<coprocess.CoprocessObject.EventReply> dispatchEvent(
        coprocess.CoprocessObject.Event request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_DISPATCH_EVENT, getCallOptions()), request);
    }
  }

  private static final int METHODID_DISPATCH = 0;
  private static final int METHODID_DISPATCH_EVENT = 1;

  private static class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final DispatcherImplBase serviceImpl;
    private final int methodId;

    public MethodHandlers(DispatcherImplBase serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_DISPATCH:
          serviceImpl.dispatch((coprocess.CoprocessObject.Object) request,
              (io.grpc.stub.StreamObserver<coprocess.CoprocessObject.Object>) responseObserver);
          break;
        case METHODID_DISPATCH_EVENT:
          serviceImpl.dispatchEvent((coprocess.CoprocessObject.Event) request,
              (io.grpc.stub.StreamObserver<coprocess.CoprocessObject.EventReply>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    return new io.grpc.ServiceDescriptor(SERVICE_NAME,
        METHOD_DISPATCH,
        METHOD_DISPATCH_EVENT);
  }

}
