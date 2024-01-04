import { NextRequest } from "next/server";
import { getServerSideConfig } from "../config/server";
import md5 from "spark-md5";
import {
  ACCESS_CODE_PREFIX,
  ModelProvider,
  ACCESS_TOKEN_PREFIX,
} from "../constant";

function getIP(req: NextRequest) {
  let ip = req.ip ?? req.headers.get("x-real-ip");
  const forwardedFor = req.headers.get("x-forwarded-for");

  if (!ip && forwardedFor) {
    ip = forwardedFor.split(",").at(0) ?? "";
  }

  return ip;
}

// try to access an api using access token
// if succeed, return true
// if failed, return false
async function validateAccessToken(accessToken: string, tokenUrl: string) {
  if (tokenUrl === "") {
    return new Promise((resolve, reject) => {
      resolve(false);
    });
  }
  return new Promise((resolve, reject) => {
    console.log("[Auth] start validating access token");
    fetch(tokenUrl + "?token=" + accessToken, {
      method: "post",
    })
      .then((response) => {
        if (response.status !== 200) {
          console.log("[Auth] validate access token error");
          resolve(false);
        } else {
          console.log("[Auth] validate access token succeeded.");
          resolve(true);
        }
      })
      .catch((err) => {
        console.log("[Auth] validate access token error");
        resolve(false);
      });
  });
}

function parseApiKey(bearToken: string) {
  const token = bearToken.trim().replaceAll("Bearer ", "").trim();
  const isApiKey =
    !token.startsWith(ACCESS_CODE_PREFIX) &&
    !token.startsWith(ACCESS_TOKEN_PREFIX);
  const isAccessToken = token.startsWith(ACCESS_TOKEN_PREFIX);

  return {
    accessCode: isApiKey ? "" : token.slice(ACCESS_CODE_PREFIX.length),
    accessToken: isAccessToken ? token.slice(ACCESS_TOKEN_PREFIX.length) : "",
    apiKey: isApiKey ? token : "",
  };
}

export async function auth(req: NextRequest, modelProvider: ModelProvider) {
  const authToken = req.headers.get("Authorization") ?? "";

  // check if it is openai api key or user token
  const { accessCode, accessToken, apiKey } = parseApiKey(authToken);

  const hashedCode = md5.hash(accessCode ?? "").trim();

  const serverConfig = getServerSideConfig();
  //console.log("[Auth] allowed hashed codes: ", [...serverConfig.codes]);
  //console.log("[Auth] got access code:", accessCode);
  //console.log("[Auth] hashed access code:", hashedCode);
  console.log("[User IP] ", getIP(req));
  //console.log("[Time] ", new Date().toLocaleString());

  if (serverConfig.allowToken && accessToken !== "") {
    let errorFlag = false;
    await validateAccessToken(accessToken, serverConfig.tokenURL ?? "").then(
      (flag) => {
        if (!flag) {
          errorFlag = true;
        }
      },
    );
    if (errorFlag) {
      return {
        error: true,
        msg: "wrong access token",
      };
    }
  }

  if (
    accessToken === "" &&
    serverConfig.needCode &&
    !serverConfig.codes.has(hashedCode) &&
    !apiKey
  ) {
    return {
      error: true,
      msg: !accessCode ? "empty access code" : "wrong access code",
    };
  }

  if (serverConfig.hideUserApiKey && !!apiKey) {
    return {
      error: true,
      msg: "you are not allowed to access with your own api key",
    };
  }

  // if user does not provide an api key, inject system api key
  if (!apiKey) {
    const serverConfig = getServerSideConfig();

    const systemApiKey =
      modelProvider === ModelProvider.GeminiPro
        ? serverConfig.googleApiKey
        : serverConfig.isAzure
        ? serverConfig.azureApiKey
        : serverConfig.apiKey;
    if (systemApiKey) {
      //console.log("[Auth] use system api key");
      req.headers.set("Authorization", `Bearer ${systemApiKey}`);
    } else {
      console.log("[Auth] admin did not provide an api key");
    }
  } else {
    console.log("[Auth] use user api key");
  }

  return {
    error: false,
  };
}
