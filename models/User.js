const mongoose = require('mongoose');
//bcrypt API 연결
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50
  },
  email: {
    type: String,
    trim: true, //띄어쓰기(빈칸)을 제거하는 역할
    unique: 1 //중복된 이메일로 등록되는 것을 막아줌
  },
  password: {
    type: String,
    minlength: 5
  },
  role: { // 예) 넘버가 1이면 관리자고 넘버가 0이면 일반유저
    type: Number,
    default: 0
  },
  image: String,
  token: { // 토큰을 이용해 나중에 유효성 관리를 할 수 있음
    type: String
  },
  tokenExp: { //토큰을 사용할 수 있는 기간
    type: Number
  }
})

//mongoose의 pre()메서드를 활용 'save'메서드가 호출되기전에 콜백함수가 실행
userSchema.pre('save', function (next) {//인자로 전달된 next는 pre메서드가 실행된 후 다시 save메서드가 호출된 위치로 실행을 넘기기 위해서 필요
  //this = userSchema
  const user = this;

  //password가 변경될 때만 비밀번호를 암호화 해주는 코드
  if (user.isModified('password')) {
    //비밀번호 암호화
    bcrypt.genSalt(saltRounds, function (err, salt) {
      //에러가 발생하면 함수를 종료하고 next메서드로 err를 전달 => user.save()로 실행을 넘김
      if (err) return next(err)

      //salt를 제대로 생성했다면 비밀번호를 해싱합니다.
      //hash의 첫번째 인자 = 사용자가 입력한 비밀번호
      //두번째 인자 = 생성한 salt
      //세번째 인자 = 콜백함수
      bcrypt.hash(user.password, salt, function (err, hash) {
        if (err) return next(err);
        //password를 hash(암호화된 비밀번호)로 변경
        user.password = hash;

        //next()안하면 save메서드가 호출된 위치로 넘어가지 않음
        next();
      });
    });
  }else{
    //비밀번호가 변경되지 않으면 암호화 해주는 코드를 실행하지 않고 next로 save가 호출된 위치로 빠져나감
    next();
  }
})

userSchema.methods.comparePassword = function(plainPassword){
  //사용자가 입력한 비밀번호와 DB에 암호화된 비밀번호가 같은지 확인
  //비밀번호가 일치하면 true, 일치하지 않으면 false를 반환
  return bcrypt.compare(plainPassword, this.password); //compare(사용자가 입력한 비밀번호, DB에서 검색한 데이터의 비밀번호)
}

//토큰을 생성하기 위해 generateToken메소드를 생성(메소드 이름은 변경 가능하다.)
userSchema.methods.generateToken = function(){
  //this = userSchema 의미
  const user = this;
  //jwt 생성
  const token = jwt.sign(user._id.toJSON(), 'secretToken');
  this.token = token;

  //생성된 토큰을 userSchema의 token필드에 넣어줌
  console.log(token)
  //save메소드로 DB에 저장하고 값을 리턴
  return this.save();
}

//주어진 토큰을 검증하고, 해당 토큰이 유효한 사용자인지 확인하는 기능을 수행
userSchema.statics.findByToken = function(token, cb){   //token = 클라이언트로부터 받은 JWT토큰, cb는 콜백함수
  //
  const user = this;

  //토큰 복호화
  jwt.verify(token, 'secretToken', function(err, decoded){
    //token을 디코드해서 userId를 사용하여 DB에서 유저를 찾는다
    user.findOne({_id:decoded, "token":token})  //클라이언트에서 가져온 token과 DB에 보관된 token이 일치하는지 확인
    
    .then((user) => {
      //token이 일치하면 err = null과 user정보를 콜백함수로 전달
      cb(null, user)
    })
    .catch((err) => {
      //token일 일치하지 않으면 콜백함수로 에러를 전달
      return cb(err);
    })
  });

}

//mongoose.model(모델의 이름, 스키마)
const User = mongoose.model('User', userSchema);

//다른 곳에도 쓸수 있게 exports 해줌
module.exports = { User }