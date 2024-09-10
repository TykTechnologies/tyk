/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package main implements a simple gRPC client that demonstrates how to use gRPC-Go libraries
// to perform unary, client streaming, server streaming and full duplex RPCs.
//
// It interacts with the route guide service whose definition can be found in routeguide/route_guide.proto.
package gateway

import (
	"context"
	"errors"
	"io"
	mathrand "math/rand"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/route_guide/routeguide"

	"github.com/TykTechnologies/tyk/test"
)

// printFeature gets the feature for the given point.
func printFeature(t *testing.T, client pb.RouteGuideClient, point *pb.Point) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	feature, err := client.GetFeature(ctx, point)
	if err != nil {
		t.Fatalf("%v.GetFeatures(_) = _, %v: ", client, err)
	}
	checkPointOk(t, feature.Location, point)
}

func eqlPoint(a, b *pb.Point) bool {
	return !(a.Longitude != b.Longitude || a.Latitude != b.Latitude)
}

func checkPointOk(t *testing.T, a, b *pb.Point) {
	t.Helper()
	if !eqlPoint(a, b) {
		t.Errorf("expected %v got %v", a, b)
	}
}

const expectedFeatures = `[{"name":"Patriots Path, Mendham, NJ 07945, USA","location":{"latitude":407838351,"longitude":-746143763}},{"name":"101 New Jersey 10, Whippany, NJ 07981, USA","location":{"latitude":408122808,"longitude":-743999179}},{"name":"U.S. 6, Shohola, PA 18458, USA","location":{"latitude":413628156,"longitude":-749015468}},{"name":"5 Conners Road, Kingston, NY 12401, USA","location":{"latitude":419999544,"longitude":-740371136}},{"name":"Mid Hudson Psychiatric Center, New Hampton, NY 10958, USA","location":{"latitude":414008389,"longitude":-743951297}},{"name":"287 Flugertown Road, Livingston Manor, NY 12758, USA","location":{"latitude":419611318,"longitude":-746524769}},{"name":"4001 Tremley Point Road, Linden, NJ 07036, USA","location":{"latitude":406109563,"longitude":-742186778}},{"name":"352 South Mountain Road, Wallkill, NY 12589, USA","location":{"latitude":416802456,"longitude":-742370183}},{"name":"Bailey Turn Road, Harriman, NY 10926, USA","location":{"latitude":412950425,"longitude":-741077389}},{"name":"193-199 Wawayanda Road, Hewitt, NJ 07421, USA","location":{"latitude":412144655,"longitude":-743949739}},{"name":"406-496 Ward Avenue, Pine Bush, NY 12566, USA","location":{"latitude":415736605,"longitude":-742847522}},{"name":"162 Merrill Road, Highland Mills, NY 10930, USA","location":{"latitude":413843930,"longitude":-740501726}},{"name":"Clinton Road, West Milford, NJ 07480, USA","location":{"latitude":410873075,"longitude":-744459023}},{"name":"16 Old Brook Lane, Warwick, NY 10990, USA","location":{"latitude":412346009,"longitude":-744026814}},{"name":"3 Drake Lane, Pennington, NJ 08534, USA","location":{"latitude":402948455,"longitude":-747903913}},{"name":"6324 8th Avenue, Brooklyn, NY 11220, USA","location":{"latitude":406337092,"longitude":-740122226}},{"name":"1 Merck Access Road, Whitehouse Station, NJ 08889, USA","location":{"latitude":406421967,"longitude":-747727624}},{"name":"78-98 Schalck Road, Narrowsburg, NY 12764, USA","location":{"latitude":416318082,"longitude":-749677716}},{"name":"282 Lakeview Drive Road, Highland Lake, NY 12743, USA","location":{"latitude":415301720,"longitude":-748416257}},{"name":"330 Evelyn Avenue, Hamilton Township, NJ 08619, USA","location":{"latitude":402647019,"longitude":-747071791}},{"name":"New York State Reference Route 987E, Southfields, NY 10975, USA","location":{"latitude":412567807,"longitude":-741058078}},{"name":"103-271 Tempaloni Road, Ellenville, NY 12428, USA","location":{"latitude":416855156,"longitude":-744420597}},{"name":"1300 Airport Road, North Brunswick Township, NJ 08902, USA","location":{"latitude":404663628,"longitude":-744820157}},{"location":{"latitude":407113723,"longitude":-749746483}},{"location":{"latitude":402133926,"longitude":-743613249}},{"location":{"latitude":400273442,"longitude":-741220915}},{"location":{"latitude":411236786,"longitude":-744070769}},{"name":"211-225 Plains Road, Augusta, NJ 07822, USA","location":{"latitude":411633782,"longitude":-746784970}},{"location":{"latitude":415830701,"longitude":-742952812}},{"name":"165 Pedersen Ridge Road, Milford, PA 18337, USA","location":{"latitude":413447164,"longitude":-748712898}},{"name":"100-122 Locktown Road, Frenchtown, NJ 08825, USA","location":{"latitude":405047245,"longitude":-749800722}},{"location":{"latitude":418858923,"longitude":-746156790}},{"name":"650-652 Willi Hill Road, Swan Lake, NY 12783, USA","location":{"latitude":417951888,"longitude":-748484944}},{"name":"26 East 3rd Street, New Providence, NJ 07974, USA","location":{"latitude":407033786,"longitude":-743977337}},{"location":{"latitude":417548014,"longitude":-740075041}},{"location":{"latitude":410395868,"longitude":-744972325}},{"location":{"latitude":404615353,"longitude":-745129803}},{"name":"611 Lawrence Avenue, Westfield, NJ 07090, USA","location":{"latitude":406589790,"longitude":-743560121}},{"name":"18 Lannis Avenue, New Windsor, NY 12553, USA","location":{"latitude":414653148,"longitude":-740477477}},{"name":"82-104 Amherst Avenue, Colonia, NJ 07067, USA","location":{"latitude":405957808,"longitude":-743255336}},{"name":"170 Seven Lakes Drive, Sloatsburg, NY 10974, USA","location":{"latitude":411733589,"longitude":-741648093}},{"name":"1270 Lakes Road, Monroe, NY 10950, USA","location":{"latitude":412676291,"longitude":-742606606}},{"name":"509-535 Alphano Road, Great Meadows, NJ 07838, USA","location":{"latitude":409224445,"longitude":-748286738}},{"name":"652 Garden Street, Elizabeth, NJ 07202, USA","location":{"latitude":406523420,"longitude":-742135517}},{"name":"349 Sea Spray Court, Neptune City, NJ 07753, USA","location":{"latitude":401827388,"longitude":-740294537}},{"name":"13-17 Stanley Street, West Milford, NJ 07480, USA","location":{"latitude":410564152,"longitude":-743685054}},{"name":"47 Industrial Avenue, Teterboro, NJ 07608, USA","location":{"latitude":408472324,"longitude":-740726046}},{"name":"5 White Oak Lane, Stony Point, NY 10980, USA","location":{"latitude":412452168,"longitude":-740214052}},{"name":"Berkshire Valley Management Area Trail, Jefferson, NJ, USA","location":{"latitude":409146138,"longitude":-746188906}},{"name":"1007 Jersey Avenue, New Brunswick, NJ 08901, USA","location":{"latitude":404701380,"longitude":-744781745}},{"name":"6 East Emerald Isle Drive, Lake Hopatcong, NJ 07849, USA","location":{"latitude":409642566,"longitude":-746017679}},{"name":"1358-1474 New Jersey 57, Port Murray, NJ 07865, USA","location":{"latitude":408031728,"longitude":-748645385}},{"name":"367 Prospect Road, Chester, NY 10918, USA","location":{"latitude":413700272,"longitude":-742135189}},{"name":"10 Simon Lake Drive, Atlantic Highlands, NJ 07716, USA","location":{"latitude":404310607,"longitude":-740282632}},{"name":"11 Ward Street, Mount Arlington, NJ 07856, USA","location":{"latitude":409319800,"longitude":-746201391}},{"name":"300-398 Jefferson Avenue, Elizabeth, NJ 07201, USA","location":{"latitude":406685311,"longitude":-742108603}},{"name":"43 Dreher Road, Roscoe, NY 12776, USA","location":{"latitude":419018117,"longitude":-749142781}},{"name":"Swan Street, Pine Island, NY 10969, USA","location":{"latitude":412856162,"longitude":-745148837}},{"name":"66 Pleasantview Avenue, Monticello, NY 12701, USA","location":{"latitude":416560744,"longitude":-746721964}},{"location":{"latitude":405314270,"longitude":-749836354}},{"location":{"latitude":414219548,"longitude":-743327440}},{"name":"565 Winding Hills Road, Montgomery, NY 12549, USA","location":{"latitude":415534177,"longitude":-742900616}},{"name":"231 Rocky Run Road, Glen Gardner, NJ 08826, USA","location":{"latitude":406898530,"longitude":-749127080}},{"name":"100 Mount Pleasant Avenue, Newark, NJ 07104, USA","location":{"latitude":407586880,"longitude":-741670168}},{"name":"517-521 Huntington Drive, Manchester Township, NJ 08759, USA","location":{"latitude":400106455,"longitude":-742870190}},{"location":{"latitude":400066188,"longitude":-746793294}},{"name":"40 Mountain Road, Napanoch, NY 12458, USA","location":{"latitude":418803880,"longitude":-744102673}},{"location":{"latitude":414204288,"longitude":-747895140}},{"location":{"latitude":414777405,"longitude":-740615601}},{"name":"48 North Road, Forestburgh, NY 12777, USA","location":{"latitude":415464475,"longitude":-747175374}},{"location":{"latitude":404062378,"longitude":-746376177}},{"location":{"latitude":405688272,"longitude":-749285130}},{"location":{"latitude":400342070,"longitude":-748788996}},{"location":{"latitude":401809022,"longitude":-744157964}},{"name":"9 Thompson Avenue, Leonardo, NJ 07737, USA","location":{"latitude":404226644,"longitude":-740517141}},{"location":{"latitude":410322033,"longitude":-747871659}},{"location":{"latitude":407100674,"longitude":-747742727}},{"name":"213 Bush Road, Stone Ridge, NY 12484, USA","location":{"latitude":418811433,"longitude":-741718005}},{"location":{"latitude":415034302,"longitude":-743850945}},{"location":{"latitude":411349992,"longitude":-743694161}},{"name":"1-17 Bergen Court, New Brunswick, NJ 08901, USA","location":{"latitude":404839914,"longitude":-744759616}},{"name":"35 Oakland Valley Road, Cuddebackville, NY 12729, USA","location":{"latitude":414638017,"longitude":-745957854}},{"location":{"latitude":412127800,"longitude":-740173578}},{"location":{"latitude":401263460,"longitude":-747964303}},{"location":{"latitude":412843391,"longitude":-749086026}},{"location":{"latitude":418512773,"longitude":-743067823}},{"name":"42-102 Main Street, Belford, NJ 07718, USA","location":{"latitude":404318328,"longitude":-740835638}},{"location":{"latitude":419020746,"longitude":-741172328}},{"location":{"latitude":404080723,"longitude":-746119569}},{"location":{"latitude":401012643,"longitude":-744035134}},{"location":{"latitude":404306372,"longitude":-741079661}},{"location":{"latitude":403966326,"longitude":-748519297}},{"location":{"latitude":405002031,"longitude":-748407866}},{"location":{"latitude":409532885,"longitude":-742200683}},{"location":{"latitude":416851321,"longitude":-742674555}},{"name":"3387 Richmond Terrace, Staten Island, NY 10303, USA","location":{"latitude":406411633,"longitude":-741722051}},{"name":"261 Van Sickle Road, Goshen, NY 10924, USA","location":{"latitude":413069058,"longitude":-744597778}},{"location":{"latitude":418465462,"longitude":-746859398}},{"location":{"latitude":411733222,"longitude":-744228360}},{"name":"3 Hasta Way, Newton, NJ 07860, USA","location":{"latitude":410248224,"longitude":-747127767}}]`

// printFeatures lists all the features within the given bounding Rectangle.
func printFeatures(t *testing.T, client pb.RouteGuideClient, rect *pb.Rectangle) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.ListFeatures(ctx, rect)
	if err != nil {
		t.Fatalf("%v.ListFeatures(_) = _, %v", client, err)
	}
	var features []*pb.Feature
	for {
		feature, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			b := test.MarshalJSON(t)(features)
			got := string(b)
			if got != expectedFeatures {
				t.Error("Failed to get features")
			}
			break
		}
		if err != nil {
			t.Fatalf("%v.ListFeatures(_) = _, %v", client, err)
		}
		features = append(features, feature)
	}
}

// runRecordRoute sends a sequence of points to server and expects to get a RouteSummary from server.
func runRecordRoute(t *testing.T, client pb.RouteGuideClient) {
	t.Helper()
	// Create a random number of random points
	r := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	pointCount := int(r.Int31n(100)) + 2 // Traverse at least two points
	var points []*pb.Point
	for i := 0; i < pointCount; i++ {
		points = append(points, randomPoint(r))
	}
	t.Logf("Traversing %d points.", len(points))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.RecordRoute(ctx)
	if err != nil {
		t.Fatalf("%v.RecordRoute(_) = _, %v", client, err)
	}
	for _, point := range points {
		if err := stream.Send(point); err != nil {
			t.Fatalf("%v.Send(%v) = %v", stream, point, err)
		}
	}
	reply, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("%v.CloseAndRecv() got error %v, want %v", stream, err, nil)
	}
	if reply.PointCount != int32(len(points)) {
		t.Errorf("PointCount: expected %d got %d", len(points), reply.PointCount)
	}
}

// runRouteChat receives a sequence of route notes, while sending notes for various locations
// this test bidirectional grpc data streaming
func runRouteChat(t *testing.T, client pb.RouteGuideClient) {
	t.Helper()
	notes := []*pb.RouteNote{
		{Location: &pb.Point{Latitude: 0, Longitude: 1}, Message: "First message"},
		{Location: &pb.Point{Latitude: 0, Longitude: 2}, Message: "Second message"},
		{Location: &pb.Point{Latitude: 0, Longitude: 3}, Message: "Third message"},
		{Location: &pb.Point{Latitude: 0, Longitude: 1}, Message: "Fourth message"},
		{Location: &pb.Point{Latitude: 0, Longitude: 2}, Message: "Fifth message"},
		{Location: &pb.Point{Latitude: 0, Longitude: 3}, Message: "Sixth message"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.RouteChat(ctx)
	if err != nil {
		t.Fatalf("%v.RouteChat(_) = _, %v", client, err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// goroutine to receive streaming data
	go func() {
		defer wg.Done()
		// lets receive some messages
		for i := 0; i < 5; i++ {
			in, err := stream.Recv()
			if err != nil {
				t.Errorf("Failed to receive a note : %v", err)
				return
			}
			t.Logf("Got message %s at point(%d, %d)", in.Message, in.Location.Latitude, in.Location.Longitude)
		}
		t.Logf("finish to receive the notes")
	}()

	// goroutine to send data
	go func() {
		defer wg.Done()
		for _, note := range notes {
			// wait some time until we send more data so we can see the parallelism
			time.Sleep(10 * time.Millisecond)
			if err := stream.Send(note); err != nil {
				t.Errorf("Failed to send a note: %v", err)
				return
			}
			t.Logf("Sending note %v", note.Message)
		}
		t.Logf("finish to send the notes")
	}()

	wg.Wait()
	t.Log("finish process, will close the stream")
	// only close the stream when we check that we're
	// receiving and sending data in bidirectional
	err = stream.CloseSend()
	if err != nil {
		t.Logf("Error closing the grpc stream: %+v", err)
	}
	t.Logf("grpc stream closed")
}

func randomPoint(r *mathrand.Rand) *pb.Point {
	lat := (r.Int31n(180) - 90) * 1e7
	long := (r.Int31n(360) - 180) * 1e7
	return &pb.Point{Latitude: lat, Longitude: long}
}

func testGRPCStreamClient(t *testing.T, addr string, opts ...grpc.DialOption) {
	t.Helper()
	opts = append(opts, grpc.WithBlock())
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		t.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewRouteGuideClient(conn)
	t.Run("Valid feature", func(t *testing.T) {
		printFeature(t, client, &pb.Point{Latitude: 409146138, Longitude: -746188906})
	})
	t.Run("Feature missing.", func(t *testing.T) {
		printFeature(t, client, &pb.Point{Latitude: 0, Longitude: 0})
	})
	t.Run("Range features", func(t *testing.T) {
		// Looking for features between 40, -75 and 42, -73.
		printFeatures(t, client, &pb.Rectangle{
			Lo: &pb.Point{Latitude: 400000000, Longitude: -750000000},
			Hi: &pb.Point{Latitude: 420000000, Longitude: -730000000},
		})
	})
	t.Run("RecordRoute", func(t *testing.T) {
		runRecordRoute(t, client)
	})
	t.Run("RouteChat", func(t *testing.T) {
		runRouteChat(t, client)
	})
}
