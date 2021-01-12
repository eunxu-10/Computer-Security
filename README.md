# Computer-Security
HYU ITE4007
-----------------------
## 1. Cryptography
  문자열 및 key를 입력 받고, 암호화 및 복호화가 가능한 경우 복호화하는 과정을 보인다.
  ### 세부 사항
  - 대칭키 암호화: DES, DES3, AES, ARC4
  - hash 함수: SHA, SHA256, SHA384, SHA512, HMAC
  - 비대칭키 암호화: RSA
  - 100자 이하의 문자열을 암호화 및 복호화 하는 과정에서 문제가 없도록 하고 입력할 때 문자열이나 key의 길이 등에 대한 입력 제한이 있는 경우는 보고서에 명시하였습니다.
  
  ### 실행 예시
  + 파일 실행 시 "original data" 문구 출력 -> 암호화 하고 싶은 메시지를 입력
    + cipher type, key를 입력 **-> encrypt와 decrpyt 출력**
    + hash type 을 입력 **-> hash 값 출력**
    + RSA 실행 -> **key 입력 -> encrpyt와 decrypt 출력**
 
 ### 환경
 - 프로그래밍 언어 : python 3.5
 - OS : windows 10
 - Ezhashlib, pycrypto, pycryptodome install 후 진행
 
 
 ## 2. Malware Classfication
  동적 분석 결과로 얻을 수 있는 API sequence를 가지고 sequence가 주어졌을 때 해당 sequence가 악성코드인지 정상파일인지 분류하는 모델을 구현하고, 해당 모델의 정확도를 계산한다.
  ### 세부 사항
  + classification 기법을 사용한다. 
    + KNN classifier
      + 입력 벡터로 tf-idf를 사용
  - **모델링 요약:** KNN classifier를 사용해서 test 문서에 대해 가장 가까운 traning data K개를 뽑고 그 data의 label에 따라서 test 문서의 label을 지정해줄 것이다. 문서의 가까운 정도를 알아내기 위해 tf-idf를 사용할 것이고 이를 위해서 Sklearn의 TfidfVectorizer모듈을 사용한다. KNN classification을 위해서 sklearn의 KNeighborsClassifier 모듈을 사용한다. 
  
  ### 순서도 
  
   ### 환경
   - 프로그래밍 언어 : python 3.5
   - OS : windows 10
   + 사용한 도구 및 모듈
      + glob: 0과 1 폴더에 있는 txt 파일을 부르기 위해서 사용
      + Matoplotlib.pyplot: KNN classifier에서 K값을 선택하기 위해서 K에 따른 정확도를 시각적으로 표현하기 위해서 사용
      + train_test_split: 학습하는 set과 검증하는 set을 분리하기 위해 사용
      + TfidfVectorizer: 문서별 단어에 대한 tf-idf값을 구하기 위해 사용
      + KNeighborsClassifier: 문서를 악성코드인지 정상 파일인지 KNN classification 방법을 이용해 분리하기 위해 사용
 
