import { create } from "zustand";
import { persist } from "zustand/middleware";
import { DEFAULT_API_HOST, DEFAULT_MODELS, StoreKey } from "../constant";
import { getHeaders } from "../client/api";
import { BOT_HELLO } from "./chat";
import { getClientConfig } from "../config/client";

export interface AccessControlStore {
  accessCode: string;
  token: string;
  accessToken: string;

  allowToken: boolean;
  needCode: boolean;
  hideUserApiKey: boolean;
  hideBalanceQuery: boolean;
  disableGPT4: boolean;

  openaiUrl: string;

  updateToken: (_: string) => void;
  updateCode: (_: string) => void;
  updateAccessToken: (_: string) => void;
  updateOpenAiUrl: (_: string) => void;
  enabledAccessControl: () => boolean;
  isAuthorized: () => boolean;
  fetch: () => void;
}

let fetchState = 0; // 0 not fetch, 1 fetching, 2 done

const DEFAULT_OPENAI_URL =
  getClientConfig()?.buildMode === "export" ? DEFAULT_API_HOST : "/api/openai/";
console.log("[API] default openai url", DEFAULT_OPENAI_URL);

export const useAccessStore = create<AccessControlStore>()(
  persist(
    (set, get) => ({
      token: "",
      accessCode: "",
      accessToken: "",
      allowToken: true,
      needCode: true,
      hideUserApiKey: false,
      hideBalanceQuery: false,
      disableGPT4: false,

      openaiUrl: DEFAULT_OPENAI_URL,

      enabledAccessControl() {
        get().fetch();

        return get().needCode;
      },
      enabledTokenValidation() {
        get().fetch();

        return get().allowToken;
      },
      updateCode(code: string) {
        set(() => ({ accessCode: code?.trim() }));
      },
      updateAccessToken(accessToken: string) {
        set(() => ({ accessToken }));
      },
      updateToken(token: string) {
        set(() => ({ token: token?.trim() }));
      },
      updateOpenAiUrl(url: string) {
        set(() => ({ openaiUrl: url?.trim() }));
      },
      isAuthorized() {
        get().fetch();

        // has token or has code has token or disabled access control
        return (
          !!get().token ||
          !!get().accessCode ||
          (get().allowToken && !!get().accessToken) ||
          !get().enabledAccessControl()
        );
      },
      fetch() {
        let urlParams = new URLSearchParams(window.location.search);
        let token = urlParams.get("access_token") || "";
        this.accessToken = token;

        if (fetchState > 0 || getClientConfig()?.buildMode === "export") return;
        fetchState = 1;
        let contextRoot = window.location.pathname.split("/")[1];
        if (contextRoot !== "") {
          contextRoot = "/" + contextRoot;
        }
        fetch(contextRoot + "/api/config", {
          method: "post",
          body: null,
          headers: {
            ...getHeaders(),
          },
        })
          .then((res) => res.json())
          .then((res: DangerConfig) => {
            console.log("[Config] got config from server", res);
            set(() => ({ ...res }));

            if (res.disableGPT4) {
              DEFAULT_MODELS.forEach(
                (m: any) => (m.available = !m.name.startsWith("gpt-4")),
              );
            }
          })
          .catch(() => {
            console.error("[Config] failed to fetch config");
          })
          .finally(() => {
            fetchState = 2;
          });
      },
    }),
    {
      name: StoreKey.Access,
      version: 1,
    },
  ),
);
