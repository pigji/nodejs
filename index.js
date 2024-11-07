const express = require("express")
const app = express();
const port = 5000;
const cors = require("cors")
//만들어 놨던 유저모델 객체를 가져옴
const { User } = require("./models/User");
//config디렉터리의 dev를 가져옴
const config = require("./config/dev");
//인증을 처리할 auth.js를 가져옴
const {auth} = require("./middleware/auth");


//생성된 토큰을 쿠키로 저장해주는 라이브러리
const cookieParser = require('cookie-parser');

app.use(cors())
app.use(express.json()) //body-parser가 express에 내장되어있으므로 바로 사용 가능
app.use(cookieParser()); //cookie-parser사용

//mongoose를 이용해서 앱과 mongoDB를 연결
const mongoose = require('mongoose')
//mongoURI값을 전달
mongoose.connect(config.mongoURI)
  .then(() => console.log("MongoDB Connected..."))
  .catch(err => console.log(err))

app.get("/", async (req, res) => {
  res.send("Hello World")
})

//회원가입 할때 필요한 정보들을 client에서 가져오고 데이터베이스에 넣어준다.
app.post('/api/users/register', async (req, res) => {
  //user 인스턴스 생성, req.body를 User인스턴스의 인자로 전달
  const user = new User(req.body);

  //save() = mongoDB에서 오는 메서드(정보들을 user모델에 저장)
  await user.save().then(() => {
    res.status(200).json({ //status(200) = 서버연결이 성공했다는 표시
      success: true
    }) //연결이 성공했으면 json형태로 success:true로 전달해 줍니다.
  }).catch((err) => {//데이터를 저장할때 에러가 발생할 경우
    res.json({success: false, err})//json형태로 success:false와 에러메시지를 전달
  })
})

//로그인 구현
app.post('/api/users/login', (req, res) => {
  //입력한 이메일과 같은 이메일 값을 가지는 데이터가 DB에 있는지 확인
  User.findOne({email: req.body.email})

  //DB에 입력한 이메일 값과 일치하는 데이터가 있으면 파라미터로 입력한 이메일과 일치하는 유저 정보를 받을 수 있다.
  .then(async (user) => {
    if(!user){
      throw new Error("요청받은 이메일에 해당하는 유저가 없습니다")
    }

    //console.log(user)
    
    //입력되는 이메일과 일치하는 유저 정보가 있으면 comparePassword메서드로 입력되는 비밀번호를 인자로 전달(이때 함수 이름은 바꿔도 된다)
    const isMatch = await user.comparePassword(req.body.password)
    
    //isMatch와 user정보를 리턴
    return {isMatch, user}
  })
  .then(({isMatch, user}) => {
    if(!isMatch){ //비밀번호가 일치하지 않으면 에러 메시지를 출력
      throw new Error("비밀번호가 틀렸습니다.")
    }
    //토큰을 생성하기 위한 메서드로 user에 generageToken메서드를 호출
    return user.generateToken();
  })
  //generageToken메서드로 새성된 토큰을 user파라미터로 받음
  .then((user) => {
    //토큰을 쿠키로 저장 res.cookie(쿠키이름, 쿠기에 저장할 데이터(토큰))
    return res.cookie("x_auth", user.token)
    //쿠키 저장에 성공하면 DB의 _id값을 전달
    .status(200)
    .json({
      loginSuccess: true,
      userId: user._id
    })
  })
  //에러가 발생하면 에러메시지 전달
  .catch((err) => {
    return res.status(400).json({
      loginSuccess: false,
      message: err.message
    })
  })
})

//auth 미들웨어 = 콜백함수가 호출되기 전에 인증처리를 하는 메소드
app.get('/api/users/auth', auth, (req, res) => {
  //auth.js에서 next()가 호출되면 auth 미들웨어에서 코드의 실행이 콜백함수로 이동됩니다.
  //여기까지 실행되었다는 의미는 Auth가 true라는 것을 의미
  res.status(200).json({
    _id: req.user._id,
    isAdmin: req.user.role === 0 ? false : true,
    isAuth: true,
    email: req.user.email,
    name: req.user.name,
    role: req.user.role,
    image: req.user.image
  })
})

//로그아웃 기능
app.get('/api/users/logout', auth, (req, res) => {
  //DB에서 id로 user를 찾고, token을 초기화 시켜줌
  User.findOneAndUpdate({_id: req.user._id}, {token: ""})
  .then(() => {
    console.log(req.user._id);
    res.status(200).send({success: true});  //로그아웃에 성공하면 success:true를 반환
  })
  .catch((err) => { //로그아웃을 실패하면 seccess: false와 에러객체를 반환
    res.json({success: false, err})
  })
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
})