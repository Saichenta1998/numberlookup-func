module.exports = async function (context, req) {
  context.log("ping invoked");
  context.res = { status: 200, body: "pong" };
};
