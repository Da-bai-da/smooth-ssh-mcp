import type { Host } from "./types.js";

export type ProcessSpec = {
  file: string;
  args: string[];
  env?: NodeJS.ProcessEnv;
  usesPassword: boolean;
};

export function wrapWithPasswordAuth(
  host: Host,
  file: "ssh" | "scp",
  args: string[],
  envSource: NodeJS.ProcessEnv = process.env
): ProcessSpec {
  if (!host.passwordEnv) {
    return { file, args, usesPassword: false };
  }

  const password = envSource[host.passwordEnv];
  if (!password) {
    throw new Error(`Host ${host.id} requires password environment variable ${host.passwordEnv}, but it is not set`);
  }

  return {
    file: "sshpass",
    args: ["-e", file, ...args],
    env: {
      ...envSource,
      SSHPASS: password
    },
    usesPassword: true
  };
}
