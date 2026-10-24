/** Messaging from the extension's own pages (popup, sign-in, unlock) to the background. */

import { browser } from "wxt/browser";
import type { UiRequest, UiResponse } from "./messages";
import type { AgentError, Reply, Request } from "./protocol";
import { describe } from "./protocol";

/** The background could not reach the agent. */
export class BridgeFailure extends Error {}

/** The agent answered with an error. */
export class AgentFailure extends Error {
  constructor(readonly info: AgentError) {
    super(describe(info));
  }
}

export async function send(message: UiRequest): Promise<UiResponse> {
  return (await browser.runtime.sendMessage(message)) as UiResponse;
}

/** One agent request through the background; throws `BridgeFailure` or `AgentFailure`. */
export async function call(request: Request): Promise<Reply> {
  const response = await send({ kind: "agent", request });
  if (response.kind === "bridge_error") throw new BridgeFailure(response.message);
  if (response.kind !== "agent") throw new Error("unexpected response from background");
  if ("err" in response.response) throw new AgentFailure(response.response.err);
  return response.response.ok;
}
