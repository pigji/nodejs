const express = require("express");
const app = express();
const port = 5000;
//만들어 놨던 유저모델 객체를 가져옴
const {User} = require("./models/User");
//config디렉터리의 dev를 가져옴
const config = require("./config/dev")

// mongodb+srv://wjlqlrll012:<db_password>@cluster0.vxfw7.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0

//mongoose를 이용해서 앱과 mongoDB를 연결
const mongoose = require('mongoose')
//mongoURI값을 전달
mongoose.connect(config.mongoURI)
  .then(() => console.log("MongoDB Connected..."))
  .catch(err => console.log(err))

app.get("/", async (req, res) => {
  const user = new User(req.body)
  console.log(user)
  res.send("Hello, World")
})
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
})

//save() = mongoDB에서 오는 메소드(정보들을 user모델에 저장)
await user.save().then(() => {
  res.status(200).json({  //status(200) = 서버연결이 성공했다는 표시
    success: true
  })  //연결이 성공했다면 json형태로 success:true로 전달해 줍니다.
}).catch((err) => { //데이터를 저장할때 에러가 발생할 경우
  res.json({success: false, err}) //json형태로 success:false와 에러 메시지를 전달
})