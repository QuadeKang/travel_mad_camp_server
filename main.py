from fastapi import Depends, FastAPI, Header, Query, Request, HTTPException, status, UploadFile, File
import secrets
from typing import Optional
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from pydantic import BaseModel
from databases import Database
from datetime import datetime
from fastapi_oauth_client import OAuthClient
from datetime import date, timedelta
import os
import shutil
from itertools import permutations
from pprint import pprint
from fastapi.staticfiles import StaticFiles

# 데이터베이스 관련 모듈
import mysql.connector
import httpx

# FastAPI 앱 인스턴스 생성
app = FastAPI(host='192.249.19.234', port=80)

# 폴더 연결 설정
app.mount("/public", StaticFiles(directory="public"), name="static")

naver_client = OAuthClient(
    client_id="i1sgslgPmM9xO83ouini",
    client_secret_id="LNN4_mUjqD",
    redirect_uri="http://172.10.7.33:80/callback_naver",
    authentication_uri="https://nid.naver.com/oauth2.0",
    resource_uri="https://openapi.naver.com/v1/nid/me",
    verify_uri="https://openapi.naver.com/v1/nid/verify",
)

kakao_client = OAuthClient(
    client_id="4b51f31a22deca51dc8bf8be09fd8b73",
    client_secret_id="03207fe4175a387a75045b014fa0f70c",
    redirect_uri="http://172.10.7.33:80/callback_kakao",
    authentication_uri="https://kauth.kakao.com/oauth",
    resource_uri="https://kapi.kakao.com/v2/user/me",
    verify_uri="https://kapi.kakao.com/v1/user/access_token_info",
)

def get_oauth_client(provider: str = Query(..., regex="naver|kakao")):
    if provider == "naver":
        return naver_client
    elif provider == "kakao":
        return kakao_client


def get_authorization_token(authorization: str = Header(...)) -> str:
    scheme, _, param = authorization.partition(" ")
    if not authorization or scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return param


async def login_required(
    oauth_client: OAuthClient = Depends(get_oauth_client),
    access_token: str = Depends(get_authorization_token),
):
    if not await oauth_client.is_authenticated(access_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    
@app.get("/naver_login")
async def login_naver(oauth_client=naver_client):
    state = secrets.token_urlsafe(32)
    login_url = oauth_client.get_oauth_login_url(state=state)
    return RedirectResponse(login_url)

@app.get("/kakao_login")
async def login_kakao(oauth_client=kakao_client):
    state = secrets.token_urlsafe(32)
    login_url = oauth_client.get_oauth_login_url(state=state)
    return RedirectResponse(login_url)

@app.get("/callback_naver")
async def callback_naver(
    code: str, state: Optional[str] = None, oauth_client=naver_client
):
    token_response = await oauth_client.get_tokens(code, state)

    return token_response

@app.get("/callback_kakao")
async def callback_kakao(
    code: str, state: Optional[str] = None, oauth_client=kakao_client
):
    token_response = await oauth_client.get_tokens(code, state)

    return token_response

@app.get("/naver_refresh")
async def callback(refresh_token: str,):
    token_response = await naver_client.refresh_access_token(
        refresh_token=refresh_token
    )

    return {"response": token_response}

@app.get("/naver/user")
async def get_user_naver(access_token: str) :

    oauth_client=naver_client
    user_info = await oauth_client.get_user_info(access_token=access_token)
    return naver_modified_info(user_info)

@app.get("/kakao/user")
async def get_user_naver(access_token: str) :

    oauth_client=kakao_client
    user_info = await oauth_client.get_user_info(access_token=access_token)
    return user_info

# 네이버 정제하기
def naver_modified_info(user_info) :
    name = user_info['response']['name']
    email = user_info['response']['email']
    gender = user_info['response']['gender']

    return name, email, gender


################################
############DATABASE############
################################

# 데이터베이스에 연결합니다.
conn = mysql.connector.connect(
    host='172.10.7.69',  # 데이터베이스 호스트
    port='80',
    user='chanelacy',  # 데이터베이스 사용자명
    password='1234',  # 데이터베이스 비밀번호
    database='sys'  # 접속하려는 데이터베이스 이름
)

@app.on_event("shutdown")
async def shutdonw_event() :

    # 데이터베이스 연결 종료
    conn.close()

# 가입한 유저인지 아닌지 확인
@app.get("/find_user")
async def find_user(access_token: str) :
    cursor = conn.cursor()

    # SQL 쿼리: 특정 tokenKey 값을 가진 레코드를 찾습니다.
    query = "SELECT EXISTS(SELECT 1 FROM USERS WHERE tokenKey = %s)"

    # 쿼리 실행
    cursor.execute(query, (access_token,))

    # 결과 가져오기 (True/False)
    exists = cursor.fetchone()[0]

    # 커서와 연결 종료
    cursor.close()
    print('true' if exists else 'false')

    # 결과 출력
    return True if exists else False

# 회원가입을 위한 데이터베이스 업데이트
@app.get("/update_new_user")
async def update_new_user(access_token: str, refresh_token: str) :
    cursor = conn.cursor()

    # 현재 날짜를 가져옵니다.
    today = date.today()
    formatted_date = today.strftime("%Y-%m-%d")

    query = """
            INSERT INTO USERS (created_at, tokenKey, refreshKey) 
            VALUES (%s, %s, %s);
            """
    cursor.execute(query, (formatted_date, access_token, refresh_token))

    conn.commit()

    # 커서와 연결 종료
    cursor.close()

@app.get("/get_user_id_by_token")
async def get_user_id_by_token(access_token: str) :
    cursor = conn.cursor()

    # 주어진 access_token으로 사용자 ID 조회
    query = "SELECT id FROM USERS WHERE tokenKey = %s;"
    cursor.execute(query, (access_token,))

    # 조회 결과
    result = cursor.fetchone()

    # 커서와 연결 종료
    cursor.close()

    if result:
        # 사용자 ID 반환
        return result[0]
    else:
        # 해당 토큰을 가진 사용자가 없는 경우
        return {"error": "User not found"}

@app.get("/update_new_nickname")
async def update_new_nickname(user_id: int, nickname: str) :
    cursor = conn.cursor()

    query = """
            INSERT INTO USERNAMES (user_id, nickname) 
            VALUES (%s, %s);
            """
    cursor.execute(query, (user_id, nickname))

    conn.commit()

    # 커서와 연결 종료
    cursor.close()

@app.get("/get_user_nickname")
async def get_user_nickname(user_id: int) :
    cursor = conn.cursor()

    # SQL 쿼리 작성: USERNAMES 테이블에서 user_id에 해당하는 nickname 검색
    query = """
    SELECT nickname FROM USERNAMES WHERE user_id = %s
    """

    # 쿼리 실행
    cursor.execute(query, (user_id,))

    # 결과 가져오기
    result = cursor.fetchone()

    # 커서와 연결 종료
    cursor.close()

    # nickname 값 반환
    return result[0]
    

@app.get("/update_new_photo")
async def update_new_photo(user_id: int, photoUrl: str) :
    cursor = conn.cursor()

    query = """
            INSERT INTO USER_PHOTO (user_id, url) 
            VALUES (%s, %s);
            """
    cursor.execute(query, (user_id, photoUrl))

    conn.commit()

    # 커서와 연결 종료
    cursor.close()

@app.get("/get_cities")
async def get_cities() :
    try :
        cursor = conn.cursor()
        # CITY 테이블에서 도시 목록 가져오기
        select_query = "SELECT NAME FROM CITY"
        cursor.execute(select_query)
        cities = [row[0] for row in cursor.fetchall()]

        cursor.close()
        
        return cities
    except mysql.connector.Error as err:
        return {"error": f"데이터베이스 오류: {err}"}

@app.get("/init_post")
async def init_post(city: str, start_day, end_day, user_id: int):
    today = date.today()
    cursor = conn.cursor()
    insert_query = """
            INSERT INTO INIT_POST (city, start_day, end_day, user_id, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """

    start_day = datetime.strptime(start_day, '%Y-%m-%d')
    end_day = datetime.strptime(end_day, '%Y-%m-%d')
    start_day = start_day.strftime('%Y-%m-%d')
    end_day = end_day.strftime('%Y-%m-%d')

    try:
        # 데이터 삽입 쿼리 실행
        cursor.execute(insert_query, (city, start_day, end_day, user_id, today))
        conn.commit()

        # 자동으로 증가된 post_index 가져오기
        cursor.execute("SELECT LAST_INSERT_ID()")
        post_index = cursor.fetchone()[0]  # 첫 번째 컬럼의 결과를 가져옴

        return post_index

    except mysql.connector.Error as err:
        return {"error": str(err), "status_code": 400}

# 좋아요 누르면 DB 업데이트
@app.get("/update_like/{post_index}")
async def update_like(post_index: int, user_index: int) :
    cursor = conn.cursor()
    insert_query = """
            INSERT INTO POST_LIKE (post_index, user_index)
            VALUES (%s, %s)
            """
    try:
        # 데이터 삽입 쿼리 실행
        cursor.execute(insert_query, (post_index, user_index))
        conn.commit()
        return 200

    except mysql.connector.Error as err:
        return 400
    pass

# 좋아요 개수 리턴해주기
@app.get("/get_like/{post_index}")
async def get_like(post_index: int) :
    cursor = conn.cursor()
    count_query = """
            SELECT COUNT(*)
            FROM POST_LIKE
            WHERE post_index = %s
            """
    try:
        # 쿼리를 실행하여 post_index의 개수를 가져옵니다.
        cursor.execute(count_query, (post_index,))
        count = cursor.fetchone()[0]
        conn.commit()
        return count
    except mysql.connector.Error as err:
        # 에러가 발생하면 400 에러와 함께 에러 메시지를 반환합니다.
        raise HTTPException(status_code=400, detail=str(err))

@app.get("/update_hotel")
async def update_hotel(post_index: int, hotel_name: str, start_day: str, end_day: str, lat: float, lng: float) :

    cursor = conn.cursor()
    insert_query = """
            INSERT INTO POST_HOTELS (post_index, hotel_name, start_day, end_day, location_lat, location_lng)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
    
    try:
        # 데이터 삽입 쿼리 실행
        cursor.execute(insert_query, (post_index, hotel_name, start_day, end_day, lat, lng))
        conn.commit()
        return 200

    except mysql.connector.Error as err:
        return 400

@app.get("/get_hotel_name")
async def get_hotel_name(hotel_index: int) :
    cursor = conn.cursor()
    find_query = """
                SELECT hotel_name FROM POST_HOTELS
                WHERE hotel_index = %s
                """
    try:
        # 데이터 조회 쿼리 실행
        cursor.execute(find_query, (hotel_index,))
        hotel_name = cursor.fetchone()  # 결과에서 한 행만 가져옵니다.
        cursor.close()
        if hotel_name:
            return hotel_name
        else:
            return {"message": "No spot found with the given location_index."}
    except mysql.connector.Error as err:
        cursor.close()
        raise HTTPException(status_code=400, detail=str(err))


@app.get("/update_spot")
async def update_spots(post_index: int, day, location_name: str, lat: float, lng: float,  vicinity: str, stars: float, reviews: int) :
    cursor = conn.cursor()
    insert_query = """
            INSERT INTO PIN_LOCATION (post_index, location_name, location_lat, location_lng, location_date, stars, nReview, vicinity)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
    
    try:
        # 데이터 삽입 쿼리 실행
        cursor.execute(insert_query, (post_index, location_name, lat, lng, day, stars, reviews, vicinity))
        conn.commit()
        return 200

    except mysql.connector.Error as err:
        return 400

@app.get("/get_spot_detail")
async def get_spot_detail(location_index: int):
    cursor = conn.cursor(dictionary=True)  # 딕셔너리 결과를 위한 설정
    select_query = """
            SELECT * FROM PIN_LOCATION
            WHERE location_index = %s
            """
    try:
        # 데이터 조회 쿼리 실행
        cursor.execute(select_query, (location_index,))
        spot_detail = cursor.fetchone()  # 결과에서 한 행만 가져옵니다.
        cursor.close()
        if spot_detail:
            return spot_detail
        else:
            return {"message": "No spot found with the given location_index."}
    except mysql.connector.Error as err:
        cursor.close()
        raise HTTPException(status_code=400, detail=str(err))

@app.get("/pin_location")
async def pin_location(post_index: int, location_lat: float, location_lng: float, name: str) :
    cursor = conn.cursor()
    insert_query = """
            INSERT INTO PIN_LOCATION (location_lat, location_lng, post_index, location_name)
            VALUES (%s, %s, %s)
            """
    try:
        # 데이터 삽입 쿼리 실행
        cursor.execute(insert_query, (location_lat, location_lng, post_index, name))
        conn.commit()
        return 200

    except mysql.connector.Error as err:
        return 400

@app.get("/update_like")
async def update_like(post_index:int, user_index: int) :
    cursor = conn.cursor()
    insert_query = """
                    INSERT INTO POST_LIKE (post_index, user_index)
                    VALUES (%s, %s)
                    """
    try:
        # 데이터 삽입 쿼리 실행
        cursor.execute(insert_query, (post_index, user_index))
        conn.commit()
        return 200

    except mysql.connector.Error as err:
        return 400

@app.get("/del_like")
async def del_like(post_index:int, user_index: int) :
    cursor = conn.cursor()
    insert_query = """
                    DELETE FROM POST_LIKE
                    WHERE post_index = %s AND user_index = %s
                    """
    try:
        # 데이터 삽입 쿼리 실행
        cursor.execute(insert_query, (post_index, user_index))
        conn.commit()
        return 200

    except mysql.connector.Error as err:
        return 400

@app.get("/get_plan_data")
async def get_plan_data(post_index: int) :
    cursor = conn.cursor(dictionary=True)
    query = """
            SELECT user_id, city, start_day, end_day
            FROM INIT_POST
            WHERE post_index = %s;
            """
    try:
        cursor.execute(query, (post_index,))
        result = cursor.fetchone()

        
        if result:
            # 날짜 차이 계산
            end_day = result['end_day']
            start_day = result['start_day']
            day_count = (end_day - start_day).days

            return {'user_id': result['user_id'], 'city': result['city'], 'day_count': day_count+1, \
            'start_day': result['start_day'], 'end_day': result['end_day']}
        else:
            return "No data found for the provided post_index"

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return 400

@app.get("/get_user_plan_data")
async def get_user_plan_data(user_index: int):
    cursor = conn.cursor(dictionary=True)
    today = datetime.now().date().strftime('%Y-%m-%d')
    query = """
            SELECT city, start_day, end_day, post_index
            FROM INIT_POST
            WHERE user_id = %s AND end_day >= %s;
            """  # end_day가 오늘 날짜 이후인 경우만 필터링
    try:
        cursor.execute(query, (user_index, today))
        result = cursor.fetchall()  # fetchone() 대신 fetchall()을 사용하여 모든 결과를 가져옵니다.

        # 결과를 원하는 형식으로 변환
        plans = []
        for row in result:
            end_day = row['end_day']
            start_day = row['start_day']
            day_count = (end_day - start_day).days
            plans.append({
                'post_index': row['post_index'],
                'city': row['city'],
                'start_day': start_day,
                'end_day': end_day,
                'day_count': day_count  # day_count도 결과에 포함시킵니다.
            })

        return plans if plans else [{}]

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return 400

@app.get("/post_detail")
async def post_detail(location_index: int, day: int, day_index: int, post_index: int, typ: str) :
    cursor = conn.cursor()
    insert_query = """
            INSERT INTO POST_SCHEDULE (location_index, day, day_index, post_index, classification)
            VALUES (%s, %s, %s, %s, %s)
            """
    try:
        # 데이터 삽입 쿼리 실행
        cursor.execute(insert_query, (location_index, day, day_index, post_index, typ))
        conn.commit()
        return 200

    except mysql.connector.Error as err:
        return 400

@app.get("/return_cities")
async def return_cities() :

    cursor = conn.cursor()
    find_query = """
    SELECT *
    FROM CITY_LOCATION
    """

    cities = []

    try:
        cursor.execute(find_query)
        data = [row for row in cursor.fetchall()]

        for x in data :
            cities.append(x[0])

        return cities

    except mysql.connector.Error as err:
        return 400

@app.get("/set_hotel")
async def set_hotel(post_index: int, hotel_name: str, start_day, end_day, location_lat: float, location_lng: float) :
    cursor = conn.cursor()
    insert_query = """
            INSERT INTO POST_HOTELS (post_index, hotel_name, start_day, end_day, location_lat, location_lng)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
    start_day = datetime.strptime(start_day, '%Y-%m-%d')
    end_day = datetime.strptime(end_day, '%Y-%m-%d')
    start_day = start_day.strftime('%Y-%m-%d')
    end_day = end_day.strftime('%Y-%m-%d')

    try:
        # 데이터 삽입 쿼리 실행
        cursor.execute(insert_query, (post_index, hotel_name, start_day, end_day, location_lat, location_lng))
        conn.commit()
        return 200

    except mysql.connector.Error as err:
        return 400

@app.get("/find_city")
async def find_city(city: str) :
    cursor = conn.cursor()
    find_query = """
    SELECT *
    FROM CITY_LOCATION
    WHERE city = (%s);
    """
    try:
        cursor.execute(find_query, (city, ))
        data = [row for row in cursor.fetchall()]

        return data[0]
    except mysql.connector.Error as err:
        return 400

@app.get("/check_like")
async def check_like(post_index: int, user_index: int):
    cursor = conn.cursor()
    check_query = """
    SELECT COUNT(*)
    FROM POST_LIKE
    WHERE post_index = %s AND user_index = %s;
    """
    try:
        cursor.execute(check_query, (post_index, user_index))
        count = cursor.fetchone()[0]

        return count > 0
    except mysql.connector.Error as err:
        return False

@app.get("/search_hotel")
async def search_places(latitude: float, longitude: float, keyword: str):
    url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json"
    params = {
        "keyword": keyword,
        "location": f"{latitude},{longitude}",
        "radius": 10000,  # 검색 반경 (미터 단위)
        "type": "lodging",
        "key": "AIzaSyBOuSiefZ0cI-wwU2rWNkbWT38M2NrxJy4"
    }



    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=params)

    result = response.json()['results']

    data = []

    for i in range(len(result)) :
        append_data = [result[i]['name'],
                        result[i]['geometry']['location']['lat'],
                        result[i]['geometry']['location']['lng'],
                        result[i]['vicinity'],
                        result[i]['rating'],
                        result[i]['user_ratings_total']]

        data.append(append_data)

    return data

@app.get("/search_place")
async def search_places(latitude: float, longitude: float, keyword: str):
    url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json"
    params = {
        "keyword": keyword,
        "location": f"{latitude},{longitude}",
        "radius": 2000,  # 검색 반경 (미터 단위)
        "key": "AIzaSyBOuSiefZ0cI-wwU2rWNkbWT38M2NrxJy4"
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=params)

    result = response.json()['results']

    data = []

    for i in range(len(result)) :
        append_data = [result[i]['name'],
                        result[i]['geometry']['location']['lat'],
                        result[i]['geometry']['location']['lng'],
                        result[i]['vicinity'],
                        result[i]['rating'],
                        result[i]['user_ratings_total']]

        data.append(append_data)

    return data

@app.get("/posts/{user_id}")
async def load_user_post(user_id: int):
    cursor = conn.cursor(dictionary=True)
    today = date.today().strftime('%Y-%m-%d')  # 오늘 날짜를 'YYYY-MM-DD' 형식으로 변환
    query = """
    SELECT 
        ip.city, 
        ip.start_day, 
        ip.end_day, 
        ip.post_index, 
        GROUP_CONCAT(ph.hash_tag) AS hash_tags, 
        COUNT(pl.post_index) AS like_count
    FROM INIT_POST ip
    LEFT JOIN POST_HASHTAG ph ON ip.post_index = ph.post_index
    LEFT JOIN POST_LIKE pl ON ip.post_index = pl.post_index
    WHERE ip.user_id = %s AND ip.end_day < %s
    GROUP BY ip.post_index
    """
    cursor.execute(query, (user_id, today))
    result = cursor.fetchall()
    cursor.close()

    # 결과를 원하는 형식으로 변환
    formatted_result = [
        {
            'city': row['city'],
            'date': f"{row['start_day']}~{row['end_day']}",
            'post_index': row['post_index'],
            'hash_tags': row['hash_tags'],
            'like_count': row['like_count']
        } for row in result
    ]
    return formatted_result

@app.get("/posts_remain/{user_id}")
async def load_remain_post(user_id: int):
    cursor = conn.cursor(dictionary=True)
    today = date.today().strftime('%Y-%m-%d')  # 오늘 날짜를 'YYYY-MM-DD' 형식으로 변환
    query = """
    SELECT 
        ip.city, 
        ip.start_day, 
        ip.end_day, 
        ip.post_index, 
        GROUP_CONCAT(ph.hash_tag) AS hash_tags, 
        COUNT(pl.post_index) AS like_count
    FROM INIT_POST ip
    LEFT JOIN POST_HASHTAG ph ON ip.post_index = ph.post_index
    LEFT JOIN POST_LIKE pl ON ip.post_index = pl.post_index
    WHERE ip.user_id = %s AND ip.end_day >= %s
    GROUP BY ip.post_index
    """
    cursor.execute(query, (user_id, today))
    result = cursor.fetchall()
    cursor.close()

    # 결과를 원하는 형식으로 변환
    formatted_result = [
        {
            'city': row['city'],
            'date': f"{row['start_day']}~{row['end_day']}",
            'post_index': row['post_index'],
            'hash_tags': row['hash_tags'],
            'like_count': row['like_count']
        } for row in result
    ]
    return formatted_result

@app.get("/all_post")
async def load_user_post():
    cursor = conn.cursor(dictionary=True)
    today = date.today().strftime('%Y-%m-%d')  # 오늘 날짜를 'YYYY-MM-DD' 형식으로 변환

    query = """
    SELECT 
        ip.city, 
        ip.start_day, 
        ip.end_day, 
        ip.post_index, 
        ip.user_id,
        u.nickname,
        GROUP_CONCAT(ph.hash_tag) AS hash_tags, 
        COUNT(pl.post_index) AS like_count
    FROM INIT_POST ip
    LEFT JOIN POST_HASHTAG ph ON ip.post_index = ph.post_index
    LEFT JOIN POST_LIKE pl ON ip.post_index = pl.post_index
    LEFT JOIN USERNAMES u ON ip.user_id = u.user_id
    WHERE ip.end_day < %s
    GROUP BY ip.post_index, u.nickname
    """
    cursor.execute(query, (today, ))
    result = cursor.fetchall()
    cursor.close()

    # 결과를 원하는 형식으로 변환
    formatted_result = [
        {
            'city': row['city'],
            'date': f"{row['start_day']}~{row['end_day']}",
            'post_index': row['post_index'],
            'user_index': row['user_id'],
            'hash_tags': row['hash_tags'],
            'like_count': row['like_count'],
            'user_name': row['nickname']
        } for row in result
    ]
    return formatted_result


@app.get("/liked_post/{user_id}")
async def load_user_post(user_id: int):
    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT 
        ip.city, 
        ip.start_day, 
        ip.end_day, 
        ip.post_index, 
        ip.user_id,
        u.nickname,
        GROUP_CONCAT(ph.hash_tag) AS hash_tags, 
        COUNT(pl.post_index) AS like_count
    FROM POST_LIKE pl
    LEFT JOIN INIT_POST ip ON pl.post_index = ip.post_index
    LEFT JOIN POST_HASHTAG ph ON ip.post_index = ph.post_index
    LEFT JOIN USERNAMES u ON ip.user_id = u.user_id
    WHERE pl.user_index = %s
    GROUP BY ip.post_index, u.nickname
    """
    cursor.execute(query, (user_id, ))
    result = cursor.fetchall()
    cursor.close()

    # 결과를 원하는 형식으로 변환
    formatted_result = [
        {
            'city': row['city'],
            'date': f"{row['start_day']}~{row['end_day']}",
            'post_index': row['post_index'],
            'user_index': row['user_id'],
            'hash_tags': row['hash_tags'],
            'like_count': row['like_count'],
            'user_name': row['nickname']
        } for row in result
    ]
    return formatted_result

# 호텔이 고정된 상태로 spot 의 최단거리 계산 후 리턴
@app.get("/return_path")
async def get_path(post_index: int) :

    days = []

    data = {
        'post_index': post_index,
    }

    cursor = conn.cursor()

    # 가용 가능한 날짜 받아오기
    get_day_query = """
                    SELECT start_day, end_day
                    FROM INIT_POST
                    WHERE post_index = %s;
                    """
    cursor.execute(get_day_query, (post_index,))
    start_day, end_day = cursor.fetchone()

    # 여행 날짜 리스트 생성
    days = get_date_range(start_day, end_day)

    data['day'] = []
    for day in days:
        # 각 날짜마다 새로운 nodes 딕셔너리를 생성하여 할당
        data['day'].append({day: {'start_hotel': [], 'spots': [], 'end_hotel': []}})

    # 호텔 정보 받아오기
    get_hotel_query = """
                    SELECT hotel_index, start_day, end_day, location_lat, location_lng
                    FROM POST_HOTELS
                    WHERE post_index = %s;
                    """
    cursor.execute(get_hotel_query, (post_index,))
    hotels_data = cursor.fetchall()
    hotels = []
    for hotel in hotels_data: hotels.append(list(hotel))

    hotels.sort(key=lambda hotel: hotel[1])

    # 호텔의 시작 날짜와 종료 날짜를 기준으로 각각 start_hotel과 end_hotel에 할당
    for i, hotel in enumerate(hotels):
        hotel_index, hotel_start, hotel_end, lat, lng = hotel

        # data['day']의 각 날짜 딕셔너리를 직접 수정
        for day_info in data['day']:
            # 현재 날짜 추출 및 datetime 객체로 변환
            day_date_str = list(day_info.keys())[0]
            day_date = parse_date(day_date_str)

            if hotel_start == start_day and hotel_start==day_date.date() :
                day_info[day_date_str]['start_hotel'] = [hotel_index, lat, lng]
                day_info[day_date_str]['end_hotel'] = [hotel_index, lat, lng]


            elif hotel_start < day_date.date() < hotel_end :
                
                day_info[day_date_str]['start_hotel'] = [hotel_index, lat, lng]
                day_info[day_date_str]['end_hotel'] = [hotel_index, lat, lng]

            # 호텔 체크인 날짜에 해당하는 날에 end_hotel 정보를 할당
            elif day_date.date() == hotel_start:
                day_info[day_date_str]['end_hotel'] = [hotel_index, lat, lng]

            elif hotel_end == end_day and hotel_end==day_date.date() :
                day_info[day_date_str]['start_hotel'] = [hotel_index, lat, lng]
                day_info[day_date_str]['end_hotel'] = [hotel_index, lat, lng]

            # 호텔 체크아웃 날짜에 해당하는 날에 end_hotel 정보를 할당
            # 체크아웃 날짜는 호텔 체크아웃 날짜와 동일하게 설정 (체크아웃의 전날이 아님)
            elif day_date.date() == hotel_end:
                day_info[day_date_str]['start_hotel'] = [hotel_index, lat, lng]


    # 호텔 정보 받아오기
    get_spot_query = """
                    SELECT location_index, location_date, location_lat, location_lng
                    FROM PIN_LOCATION
                    WHERE post_index = %s;
                    """
    cursor.execute(get_spot_query, (post_index,))
    spots_data = cursor.fetchall()
    spots = []
    for spot in spots_data: spots.append(list(spot))
    print(spots)
    pprint(data)

    for spot in spots:
        spot_index, spot_date, lat, lng = spot

        # spot_date를 문자열로 변환 (데이터베이스에서 반환된 형식에 따라 변경할 수 있음)
        spot_date_str = str(spot_date)

        # data['day']의 각 날짜 딕셔너리를 검사하여 일치하는 날짜에 spot 추가
        for day_info in data['day']:
            day_date_str = list(day_info.keys())[0]  # 현재 날짜 추출

            if day_date_str == spot_date_str:
                day_info[day_date_str]['spots'].append([spot_index, lat, lng])
    
    for day_info in data['day']:
        # 현재 처리하는 날짜를 추출합니다.
        day_date_str = list(day_info.keys())[0]
        
        # 현재 날짜의 start_hotel, spots, end_hotel을 추출합니다.
        start_hotel = day_info[day_date_str]['start_hotel']
        spots = day_info[day_date_str]['spots']
        end_hotel = day_info[day_date_str]['end_hotel']
        
        # 시작 호텔, 스팟들, 종료 호텔을 하나의 노드 리스트로 결합합니다.
        nodes = [start_hotel] + spots + [end_hotel]

        print(nodes)

        # 노드 리스트를 사용하여 최단 경로를 찾습니다.
        shortest_path = find_shortest_path(nodes)

        # data에 최단 경로로 업데이트된 spots 정보를 저장합니다.
        # 이때, 시작 호텔과 종료 호텔을 제외합니다.
        day_info[day_date_str]['spots'] = shortest_path[1:-1]

    return data

def parse_date(date_string):
    return datetime.strptime(date_string, '%Y-%m-%d')

def get_date_range(start, end):
    # 날짜 형식을 datetime 객체로 변환
    start_date = start
    end_date = end

    # 각 날짜를 저장할 리스트 초기화
    date_list = []

    # start_date부터 end_date까지 반복하며 모든 날짜 추가
    while start_date <= end_date:
        date_list.append(start_date.strftime('%Y-%m-%d'))
        start_date += timedelta(days=1)  # 다음 날로 이동

    return date_list

def find_shortest_path(nodes):
    # Calculate Euclidean distance between two points
    def distance(a, b):
        return ((a[1] - b[1])**2 + (a[2] - b[2])**2)**0.5

    # Calculate total distance for a path
    def total_distance(points):
        return sum(distance(point, points[i + 1]) for i, point in enumerate(points[:-1]))

    # Extract the start and end nodes
    start_node = nodes[0]
    end_node = nodes[-1]

    # Generate all permutations of the middle nodes
    middle_nodes = nodes[1:-1]
    all_middle_paths = permutations(middle_nodes)
    
    # Track the shortest path and its distance
    shortest_path = None
    shortest_distance = float('inf')

    # Check each possible path for the middle nodes
    for middle_path in all_middle_paths:
        # Construct the full path with the start and end nodes
        full_path = [start_node] + list(middle_path) + [end_node]

        # Calculate the total distance for this path
        path_distance = total_distance(full_path)

        # Update shortest path if this path is shorter
        if path_distance < shortest_distance:
            shortest_distance = path_distance
            shortest_path = full_path

    return shortest_path


################################
############STORAGE############
################################

# 프로파일 사진 서버에 올리기
@app.post("/profile_photo/")
async def upload_file(file: UploadFile = File(...)):
    upload_folder = 'static/profile'
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    return {"file_path": file_path}

# 프로파일 사진 다운로드 받기
@app.get("/download/{file_name}")
async def download_file(file_name: str):
    file_path = os.path.join('static/profile', file_name)
    return FileResponse(path=file_path, filename=file_name)

# 게시글 이미지 사진 올리기
@app.post("/post_photo/")
async def post_photo(file: UploadFile = File(...)):
    upload_folder = 'post_photo'
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    return {"file_path": file_path}

# 게시글 사진 다운받기
@app.get("/download_post_image/{post_index}.jpg")
async def download_post_image(post_index: str):
    file_path = os.path.join('post_photo', '{post_index}.jpg')
    return FileResponse(path=file_path, filename='{post_index}.jpg')
