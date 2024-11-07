const mongoose = require("mongoose");

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50
  },
  email: {
    type: String,
    trim : true,  //띄어쓰기를 제거하는 역할
    unique: 1 //중복된 이메징ㄹ 주소를 허용하지 않겠다는 의미
  },
  password: {
    type: String,
    minlength: 5  //5글자 이상으로 설정
  },
  role: { //예시) nub가 1이면 관리자, 0이면 일반유저
    type: Number,
    default: 0
  },
  image: String,
  token: {  //토큰을 이요해서 나중에 유효성 관리를 할 수 있음
    type: String,
  },
  tokenExp: { //토큰을 사용할 수 있는 기간
    type: Number
  }
});

//mongoose.model(모델의 이름, 스키마)
const User = mongoose.model('User', userSchema);

//다른 곳에서 쓸 수 있게 exports해줌
module.exports = {User}