import json
import boto3
import botocore
import uuid
import bcrypt
import jwt
import os
import requests
import urllib
import geohash2
import datetime
import decimal
from boto3.dynamodb.conditions import Attr
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from amadeus import Client, ResponseError, Location
from decimal import *

JWT_SECRET = os.getenv('JWT_SECRET')
AMADEUS_ID = os.getenv('AMADEUS_ID')
AMADEUS_SECRET = os.getenv('AMADEUS_SECRET')

def get_users(event, context):
    
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("Users")

    items = table.scan()['Items']

    for item in items:
        if type(item['password']) != str:
            item['password'] = item['password'].value.decode('utf-8')        

    response = {
        "statusCode": 200,
        "body": json.dumps(items),
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        }
    }

    return response


def register(event, context):

    payload = json.loads(event['body'])
    user_id = str(uuid.uuid4())
    username = payload['username']
    password = payload['password']
    email = payload['email']
    first_name = payload['first_name']
    last_name = payload['last_name']

    hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    message = "Sucessful"

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("Users")
    publicTable = dynamodb.Table("publicUsers")

    try:
        items = table.scan(
            FilterExpression=Key('username').eq(username)
        )['Items']
    except ClientError as e:
        message = 'ERROR: Username or Email was not unique'

    if len(items) == 0:
        table_response = table.put_item(
            Item = {
                'user_id': user_id,
                'username': username,
                'password': hashedPassword,
                'email': email,
                'first_name': first_name,
                'last_name': last_name
            }
        )

        response2 = publicTable.put_item(
            Item = {
                'username': username,
                'friend_requests': [],
                'friends': [],
                'posts': [],
                'events': []
            }
        )
    else:
        message = 'ERROR: Username or Email was not unique'

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            "status": message
        })
    }

    return response

def login1(event, context):

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("Users")

    payload = json.loads(event['body'])
    username = payload['username']
    password = payload['password']

    error = False
    
    try:
        items = table.scan(
            FilterExpression=Key('username').eq(username)
        )['Items']
    except ClientError as e:
        error = True

    if error == True:
        message = "Invalid Username and Password Combination"
        token = "N/A"
    else:
        
        if len(items) != 0:

            user_password = items[0]['password'].value.decode('utf-8')
            
            if bcrypt.checkpw(password.encode('utf-8'), user_password.encode('utf-8')):
                message = "sucessful"
                setup = {}

                setup['user'] = str(items[0]['username'])
                setup['exp'] = datetime.utcnow() + timedelta(seconds=1800)

                jwt_token = jwt.encode(setup, 'secret','HS256')
                token = jwt_token.decode('utf-8')

            else:
                message = "Invalid Username and Password Combination"
                token = "N/A"
        
        else:
             message = "Invalid Username and Password Combination"
             token = "N/A"

    response = {
        "statusCode": 200,
        "body": json.dumps({
            "message" : message,
            "token": token
        }),
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        }
    }

    return response

def create_post(event, context):
    
    payload = json.loads(event['body'])
    username = payload['id']
    title = payload['title']
    description = payload['desc']



    response = {
        "statusCode": 200,
        "body": json.dumps({
            'message': "hello"
        }),
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        }
    }

    return response


def find_airports(event, context):

    payload = json.loads(event['body'])
    city1 = payload['city1']
    city2 = payload['city2']

    amadeus = Client(
        client_id=AMADEUS_ID,
        client_secret=AMADEUS_SECRET
    )

    try:
        response = amadeus.reference_data.locations.get(
            keyword=city1,
            subType=Location.ANY
        )
        data = response.data
    except ResponseError as error:
        data = error

    list_airports1 = []

    for airport in data:
        if airport['subType'] == "AIRPORT":
            ap = {
                "name": airport['name'],
                "iataCode": airport['iataCode']
            }

            if ap not in list_airports1:
                list_airports1.append(ap)

    try:
        response = amadeus.reference_data.locations.get(
            keyword=city2,
            subType=Location.ANY
        )
        data = response.data
    except ResponseError as error:
        data = error

    list_airports2 = []

    for airport in data:
        if airport['subType'] == "AIRPORT":
            ap = {
                "name": airport['name'],
                "iataCode": airport['iataCode']
            }

            if ap not in list_airports2:
                list_airports2.append(ap)

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            'airports1': list_airports1,
            'airports2': list_airports2
        })
    }

    return response



def get_flight(event, context):

    payload = json.loads(event['body'])
    origin = payload['origin']
    destination = payload['destination']
    leave_date = payload['leave_date']
    back_date = payload['back_date']
    numAdults = payload['numAdults']

    amadeus = Client(
        client_id=AMADEUS_ID,
        client_secret=AMADEUS_SECRET
    )

    try:
        response = amadeus.shopping.flight_offers_search.get(
            originLocationCode=origin,
            destinationLocationCode=destination,
            departureDate=leave_date,
            adults=numAdults
        )
        data = response.data
    except ResponseError as error:
        data = error

    flight = data[0]
    fdata = {
        "Cost": flight['price']['total'],
        "Airline": flight['validatingAirlineCodes'],
        "DRP": flight["itineraries"][0]["segments"][0]["departure"],
        "ARV": flight["itineraries"][0]["segments"][0]["arrival"]
    }
    to_flight = fdata

    try:
        response = amadeus.shopping.flight_offers_search.get(
            originLocationCode=destination,
            destinationLocationCode=origin,
            departureDate=back_date,
            adults=numAdults
        )
        data = response.data
    except ResponseError as error:
        data = error

    flight = data[0]
    fdata = {
        "Cost": flight['price']['total'],
        "Airline": flight['validatingAirlineCodes'],
        "DRP": flight["itineraries"][0]["segments"][0]["departure"],
        "ARV": flight["itineraries"][0]["segments"][0]["arrival"]
    }
    back_flight = fdata

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            'to': to_flight,
            'back': back_flight
        })
    }

    return response

def getEvents(event, context):

    payload = json.loads(event['body'])
    a = payload['address']
    d = payload['date']

    #a = 'Paris'
    #d = '2020-09-01'

    events_name = []
    events_list = []
    address = urllib.parse.urlencode({"address": a})
    date = d + 'T00:00:00Z' 

    url = 'https://maps.googleapis.com/maps/api/geocode/json?' + address + '&key=AIzaSyDX0Us0bZyz6wX8gSBJgeqIY9m7RJfji1k'
    response = requests.get(url)
    location = response.json()['results'][0]['geometry']['location']

    geohash = geohash2.encode(location['lat'], location['lng'], precision=3)

    r = requests.get('https://app.ticketmaster.com/discovery/v2/events.json?' + urllib.parse.urlencode({"geoPoint": geohash}) + '&' + urllib.parse.urlencode({'startDateTime': date}) + '&apikey=TSz3OsjHtFMCD0O5CXKOUsOXwEHtuG4Q')

    if len(r.json()['_embedded']['events']) > 0:

        for event in r.json()['_embedded']['events']:
            if event['name'] not in events_name:
                e = {
                        "name": event['name'],
                        "type": event['classifications'][0]['segment']['name'].replace('_', ' '),
                        "date": event['dates']['start']['dateTime'],
                        "location": event['_embedded']['venues'][0]['city']['name'],
                    }

                if 'priceRanges' in event:
                    e["cost"] = str(event['priceRanges'][0]['min'])
                else:
                    e["cost"] = None
                

                events_name.append(event['name'])
                events_list.append(e)

    seatgeek_location = urllib.parse.urlencode({'lat': location['lat'], 'lon': location['lng']})
    url = 'https://api.seatgeek.com/2/events?client_id=MjExNjQ0MzJ8MTU4Nzg4Nzg1NC40Mw&client_secret=8359bb16842ecf337f0d13036c4b885e5e103264b5374450d3ed7b6c0fdc3799&' + seatgeek_location + '&datetime_utc.gt=' + date
    r = requests.get(url)

    if len(r.json()['events']) > 0:

        for event in r.json()['events']:
            if event['title'] not in events_name:
                
                e = {
                    "name": event['title'],
                    "type": event['type'].replace('_', ' '),
                    "date": event['datetime_utc'],
                    "location": event['venue']['city'],
                    "cost": str(event['stats']['average_price'])
                }

                events_name.append(event['title'])
                events_list.append(e)

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            'events': events_list
        })
    }

    return response

def home(event, context):

    payload = json.loads(event['body'])
    username = payload['username']

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("publicUsers")

    try:
        items = table.scan(
            FilterExpression=Key('username').eq(username)
        )['Items']
    except ClientError as e:
        error = True

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            'user_info': items[0]
        })
    }

    return response

def createPlan(event, context):
    payload = json.loads(event['body'])
    
    username = payload['username']
    planName = payload['name']
    startingDate = payload['startDate']
    endingDate = payload['endDate']

    #username = "chris"
    #planName = "Italy 2021"
    #startingDate = "2020-09-10"
    #endingDate = "2020-09-20"

    plan_id = str(uuid.uuid4())
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    publicTable = dynamodb.Table("publicUsers")

    r1 = publicTable.update_item(
        Key={
            'username': username
        },
        UpdateExpression="SET events = list_append(events, :i)",
        ExpressionAttributeValues={
            ':i': [plan_id]
        },
    )

    plansTable = dynamodb.Table("plans")

    r2 = plansTable.put_item(
        Item = {
                'planID': plan_id,
                'startDate': startingDate,
                'endDate': endingDate,
                'cost': 0,
                'friends': [username],
                'airfare': [],
                'hotel': [],
                'events': [],
                'planName': planName
            }
    )

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            'message': 'added'
        })
    }

    return response

def addEvent(event, context):
    
    payload = json.loads(event['body'])
    plan_id = payload['planID']
    event = payload['event']

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    plansTable = dynamodb.Table("plans")

    cost = 0

    for e in [event]:
        cost += Decimal(e['cost'])

    r1 = plansTable.update_item(
        Key={
            'planID': plan_id
        },
        UpdateExpression="SET events = list_append(events, :i)",
        ExpressionAttributeValues={
            ':i': [event]
        },
    )

    r2 = plansTable.update_item(
        Key={
            'planID': plan_id
        },
        UpdateExpression="ADD cost :q",
        ExpressionAttributeValues={
            ':q': cost,
        },
    )

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            'message': 'added'
        })
    }

    return response

def getPlanDetails(event, context):

    class DecimalEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, decimal.Decimal):
                return float(o)
            return super(DecimalEncoder, self).default(o)

    payload = json.loads(event['body'])
    plan_id = payload['planID']
    #plan_id = 'f977b1bb-9c4a-4b44-9f52-f205735b37c1'

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    plansTable = dynamodb.Table("plans")

    item = plansTable.scan(
            FilterExpression=Key('planID').eq(plan_id)
        )['Items']

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps(item, cls=DecimalEncoder)
    }

    return response


def addFlight(event, context):
    
    payload = json.loads(event['body'])
    plan_id = payload['planID']
    flight = payload['flight']    

    cost = 0

    for f in flight:
        cost += Decimal(f['Cost'])

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    plansTable = dynamodb.Table("plans")

    r1 = plansTable.update_item(
        Key={
            'planID': plan_id
        },
        UpdateExpression="SET airfare = list_append(airfare, :i)",
        ExpressionAttributeValues={
            ':i': flight,
        },
    )

    r2 = plansTable.update_item(
        Key={
            'planID': plan_id
        },
        UpdateExpression="ADD cost :q",
        ExpressionAttributeValues={
            ':q': cost,
        },
    )

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            'message': 'added'
        })
    }

    return response

def findHotels(event, context):
    payload = json.loads(event['body'])
    city = payload['city']
    #city = 'New York'

    address = urllib.parse.urlencode({"address": city})
    url = 'https://maps.googleapis.com/maps/api/geocode/json?' + address + '&key=AIzaSyDX0Us0bZyz6wX8gSBJgeqIY9m7RJfji1k'
    r = requests.get(url)
    location = r.json()['results'][0]['geometry']['location']

    amadeus = Client(
        client_id=AMADEUS_ID,
        client_secret=AMADEUS_SECRET
    )

    try:
        response = amadeus.shopping.hotel_offers.get(latitude=location['lat'], longitude=location['lng'], radius='20', radiusUnit='MILE')
        print(response.data)
    except ResponseError as error:
        print(error)

    hotels = []
    
    for hotel in response.data:
        h = {
            "name": hotel["hotel"]["name"],
            "rating": hotel["hotel"]["rating"],
            "city": hotel["hotel"]["address"]["cityName"],
            "cost": hotel["offers"][0]["price"]["total"]
        }

        hotels.append(h)

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            'hotels': hotels
        })
    }

    return response

def addHotel(event, context):
    
    payload = json.loads(event['body'])
    plan_id = payload['planID']
    h = payload['hotel']    

    cost = Decimal(h['cost'])

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    plansTable = dynamodb.Table("plans")

    r1 = plansTable.update_item(
        Key={
            'planID': plan_id
        },
        UpdateExpression="SET hotel = list_append(hotel, :i)",
        ExpressionAttributeValues={
            ':i': [h],
        },
    )

    r2 = plansTable.update_item(
        Key={
            'planID': plan_id
        },
        UpdateExpression="ADD cost :q",
        ExpressionAttributeValues={
            ':q': cost,
        },
    )

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            'message': 'added'
        })
    }

    return response

def send_friend_request(event, context):

    payload = json.loads(event['body'])
    #payload = event
    fromUsername = payload['fromUsername']
    toUsername = payload['toUsername']

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("publicUsers")

    message = "Success"

    result = table.update_item(
        Key={
            'username': toUsername
        },
        UpdateExpression="SET friend_requests = list_append(friend_requests, :i)",
        ExpressionAttributeValues={
            ':i': [fromUsername]
        },
        ReturnValues="UPDATED_NEW"
    )
    if result['ResponseMetadata']['HTTPStatusCode'] != 200:
        message = "Failed"

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            "status": message
        })
    }

    return response

def accept_friend_request(event, context):
    # when accepting we take in a request_id and a update both toUsername and fromUsername to have eachother in friends table

    payload = json.loads(event['body'])
    #payload = event
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("publicUsers")

    fromUsername = payload['fromUsername']
    toUsername = payload['toUsername']

    message = "Success"

    #get item of toUsername from publicUsers
    response = table.get_item(
        Key={
            'username': toUsername
        }
    )
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        message = "Failed in getting Index"

    friendReqList = response['Item']['friend_requests']

    #find the index of fromUsername
    count = 0
    indexFrom = 0
    for req in friendReqList:
        if req == fromUsername:
            indexFrom = count
        count += 1

    stringExpresion = "REMOVE friend_requests[" + str(indexFrom) + "]"

    #remove the friend request by index
    result = table.update_item(
        Key={
            'username': toUsername
        },
        UpdateExpression=stringExpresion
    )
    if result['ResponseMetadata']['HTTPStatusCode'] != 200:
        message = "Failed in removing request"

    #inserts friend into fromUsername key
    result = table.update_item(
        Key={
            'username': fromUsername
        },
        UpdateExpression="SET friends = list_append(friends, :i)",
        ExpressionAttributeValues={
            ':i': [toUsername]
        },
        ReturnValues="UPDATED_NEW"
    )
    if result['ResponseMetadata']['HTTPStatusCode'] != 200:
        message = "Failed at inserting friend into fromUsername"

    #inserts friend into toUsername key
    result = table.update_item(
        Key={
            'username': toUsername
        },
        UpdateExpression="SET friends = list_append(friends, :i)",
        ExpressionAttributeValues={
            ':i': [fromUsername]
        },
        ReturnValues="UPDATED_NEW"
    )
    if result['ResponseMetadata']['HTTPStatusCode'] != 200:
        message = "Failed at inserting friend into toUsername"

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            "status": message
        })
    }

    return response


def get_friend_requests(event, context):
    # when we get friend request we wanna return request_id, fromUsername so when we accept the request we can just pass in the req_id to be deleted
    #pass in username only

    payload = json.loads(event['body'])
    #payload = event
    toUsername = payload['username']

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("publicUsers")

    #get item of toUsername from publicUsers
    response = table.get_item(
        Key={
            'username': toUsername
        }
    )

    friendReqList = response['Item']['friend_requests']

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps(friendReqList)
    }

    return response


def get_hotel_city(event, context):
    #format:
    #'cityName': 'cityName'

    amadeus = Client(
        client_id='jRfuscAlEGTr79S9bWUVED66wdGCErku',
        client_secret='XCC7I0GCfVIz7jAr'
    )

    payload = json.loads(event['body'])
    #payload = event
    cityName = payload['cityName']

    locationList = []

    try:
        response = amadeus.reference_data.locations.get(keyword=cityName, subType=Location.ANY)

        for element in response.data:
            location = {}
            location['cityCode'] = element['address']['cityCode']

            if('stateCode' in element['address']):
                location['cityName'] = ("%s, %s %s" % (element['address']['cityName'], element['address']['stateCode'], element['address']['countryCode']))
            else:
                location['cityName'] = ("%s, %s " % (element['address']['cityName'], element['address']['countryCode']))

            if location not in locationList:
                locationList.append(location)

    except ResponseError as error:
        response = {
            "message": "Failed"
        }
        return response

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps(locationList)
    }
    return response


def get_hotels(event, context):

    #format:
    #'cityCode': 'cityCode'

    amadeus = Client(
        client_id='jRfuscAlEGTr79S9bWUVED66wdGCErku',
        client_secret='XCC7I0GCfVIz7jAr'
    )

    payload = json.loads(event['body'])
    #payload = event
    cityCode = payload['cityCode']

    hotelList = []

    try:
        # Get list of Hotels by city code
        hotels_by_city = amadeus.shopping.hotel_offers.get(cityCode=cityCode)

        for element in hotels_by_city.data:
            hotelObj = {}

            hotel_id = element['hotel']['hotelId']
            name = element['hotel']['name']
            distance = ("%s %s"%(element['hotel']['hotelDistance']['distance'], element['hotel']['hotelDistance']['distanceUnit']))
            rating = element['hotel']['rating']
            price = ("%s %s"%(element['offers'][0]['price']['total'], element['offers'][0]['price']['currency']))
            roomDesc = element['offers'][0]['room']['description']['text']

            hotelObj['name'] = name
            hotelObj['rating'] = rating
            hotelObj['distance'] = distance
            hotelObj['price'] = price
            hotelObj['hotel_id'] = hotel_id

            if hotelObj not in hotelList:
                hotelList.append(hotelObj)


    except ResponseError as error:
        response = {
            "message": "ERROR",
            "code": error
        }
        return response

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps(hotelList)
    }

    return response

def get_hotel_offers(event, context):
    #format:
    #'id': 'hotel ID'
    #'checkInDate': 'checkInDate'
    #'checkOutDate': 'checkOutDate'

    amadeus = Client(
        client_id='jRfuscAlEGTr79S9bWUVED66wdGCErku',
        client_secret='XCC7I0GCfVIz7jAr'
    )

    payload = json.loads(event['body'])
    #payload = event
    id = payload['id']
    inDate = payload['checkInDate']
    outDate = payload['checkOutDate']

    offerList = []

    try:
        hotel_offers = amadeus.shopping.hotel_offers_by_hotel.get(hotelId=id, checkInDate=inDate, checkOutDate=outDate)
        hotelData = hotel_offers.data['hotel']
        offersData = hotel_offers.data['offers']

        hotelName = "%s in %s, %s"%(hotelData['name'],hotelData['address']['cityName'],hotelData['address']['stateCode'] )
        offerList.append(hotelName)
        for element in offersData:
            hotelObj = {}

            hotelObj['price'] = "%s %s"%(element['price']['total'],element['price']['currency'])
            hotelObj['beds'] = "%s %s"%(element['room']['typeEstimated']['beds'], element['room']['typeEstimated']['bedType'])
            hotelObj['guests'] = "%s Adults"% (element['guests']['adults'])
            hotelObj['checkInDate'] = element['checkInDate']
            hotelObj['checkOutDate'] = element['checkOutDate']
            hotelObj['link'] = element['self']

            if hotelObj not in offerList:
                offerList.append(hotelObj)


    except ResponseError as error:
        print(error)
        pass

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps(offerList)
    }

    return response


def user_serch(event, context):
    #format:
    #'name': 'searched username'

    payload = json.loads(event['body'])
    #payload = event
    inputName = payload['name']

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("publicUsers")

    items = table.scan()['Items']

    usernames = []
    matchedUsernames = []

    for item in items:
        usernames.append(item['username'])

    for name in usernames:
        if inputName in name:
            matchedUsernames.append(name)

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps(matchedUsernames)
    }

    return response


def send_message(event, context):

    payload = json.loads(event['body'])
    #payload = event
    # current date and time
    now = datetime.now()
    timestamp = int(datetime.timestamp(now))
    event_id = payload['event_id']
    username = payload['username']
    content = payload['message']
    index = 0
    message = "Sucessful"

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("messages")

    try:
        # Get the next message index
        response = table.query(KeyConditionExpression="event_id = :room",
                ExpressionAttributeValues={":room": event_id},
                Limit=1, ScanIndexForward=False)
        items = response.get("Items", [])
        index = items[0]["index"] + 1 if len(items) > 0 else 0
    except ResponseError as e:
        message = 'ERROR: Indexing failed'


    table_response = table.put_item(
        Item = {
            'event_id': event_id,
            'content': content,
            'index': index,
            'time': timestamp,
            'username': username
        }
    )

    # Get the 1st most recent chat messages
    response = table.query(KeyConditionExpression="event_id = :room",
            ExpressionAttributeValues={":room": event_id},
            Limit=1, ScanIndexForward=False)
    items = response.get("Items", [])
    messages = []
    # Extract the relevant data and order chronologically

    for x in items:
        time = x["time"]
        timestamp = str(datetime.fromtimestamp(time))
        messages.append({"username": x["username"], "content": x["content"], "time": timestamp})
    messages.reverse()


    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps(messages)
    }

    return response


def get_messages(event, context):
    #pass in: event_id

    payload = json.loads(event['body'])
    #payload = event
    event_id = payload['event_id']


    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table("messages")

    # Get all the most chat messages
    response = table.query(KeyConditionExpression="event_id = :room",
            ExpressionAttributeValues={":room": event_id},
            ScanIndexForward=False)
    items = response.get("Items", [])
    messages = []

    # Extract the relevant data and order chronologically

    for x in items:
        time = x["time"]
        timestamp = str(datetime.fromtimestamp(time))
        messages.append({"username": x["username"], "content": x["content"], "time": timestamp})
    messages.reverse()


    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps(messages)
    }

    return response

def addFriendToPlan(event, context):
    payload = json.loads(event['body'])
    planID = payload['planID']
    friend = payload['friend']

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    plansTable = dynamodb.Table("plans")

    r1 = plansTable.update_item(
        Key={
            'planID': planID
        },
        UpdateExpression="SET friends = list_append(friends, :i)",
        ExpressionAttributeValues={
            ':i': [friend],
        },
    )

    publicUsers = dynamodb.Table("publicUsers")

    r2 = publicUsers.update_item(
        Key={
            'username': friend
        },
        UpdateExpression="SET events = list_append(events, :i)",
        ExpressionAttributeValues={
            ':i': [planID],
        },
    )

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': "true",
        },
        "body": json.dumps({
            "message": "added"
        })
    }

    return response