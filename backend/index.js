const SESSION_DAYS = 30;
const MAX_BODY_SIZE = 1024 * 1024;
const MAX_NAME_LENGTH = 40;
const MAX_AVATAR_LENGTH = 100;

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: cors
  });
}

function randomString(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  let binary = "";

  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function hash(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function newRecoveryCode() {
  const value = randomString(24);
  return "EF-" + value.match(/.{1,8}/g).join("-");
}

function expiryDate() {
  const date = new Date();
  date.setDate(date.getDate() + SESSION_DAYS);
  return date.toISOString();
}

async function readBody(request) {
  const text = await request.text();

  if (new TextEncoder().encode(text).length > MAX_BODY_SIZE) {
    throw new Error("Payload too large");
  }

  const body = JSON.parse(text);

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("Invalid request body");
  }

  return body;
}

function validateProfile(name, avatar) {
  if (
    typeof name !== "string" ||
    !name.trim() ||
    name.trim().length > MAX_NAME_LENGTH
  ) {
    return null;
  }

  if (
    typeof avatar !== "string" ||
    !avatar.trim() ||
    avatar.trim().length > MAX_AVATAR_LENGTH
  ) {
    return null;
  }

  return {
    displayName: name.trim(),
    avatar: avatar.trim()
  };
}

async function createSession(env, userId) {
  const token = randomString(32);
  const tokenHash = await hash(token);
  const expires = expiryDate();

  await env.DB.prepare(`
    INSERT INTO sessions
    (session_id, user_id, token_hash, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(
    crypto.randomUUID(),
    userId,
    tokenHash,
    expires
  ).run();

  return { token, expires };
}

async function authenticate(request, env) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);

  if (!match) return null;

  const tokenHash = await hash(match[1]);

  return await env.DB.prepare(`
    SELECT user_id, session_id
    FROM sessions
    WHERE token_hash = ? AND expires_at > ?
  `).bind(
    tokenHash,
    new Date().toISOString()
  ).first();
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // HEALTH CHECK
      if (path === "/" || path === "/api/health") {
        return json({
          app: "EduFocus",
          status: "online",
          databaseConfigured: !!env.DB
        });
      }

      if (!env.DB) {
        return json({
          error: "Database not configured"
        }, 503);
      }

      // CREATE GUEST ACCOUNT
      if (
        path === "/api/guest/create" &&
        request.method === "POST"
      ) {
        const body = await readBody(request);

        const profile = validateProfile(
          body.displayName,
          body.avatar
        );

        if (!profile) {
          return json({
            error: "A valid display name and avatar are required"
          }, 400);
        }

        const userId = crypto.randomUUID();
        const recoveryCode = newRecoveryCode();
        const recoveryHash = await hash(recoveryCode);

        // Create user and initial data
        await env.DB.batch([
          env.DB.prepare(`
            INSERT INTO users
            (user_id, recovery_code_hash, display_name, avatar)
            VALUES (?, ?, ?, ?)
          `).bind(
            userId,
            recoveryHash,
            profile.displayName,
            profile.avatar
          ),

          env.DB.prepare(`
            INSERT INTO user_data
            (user_id, core_data, addon_data)
            VALUES (?, '{}', '{}')
          `).bind(userId)
        ]);

        const session = await createSession(env, userId);

        return json({
          success: true,
          userId,
          profile: {
            name: profile.displayName,
            avatar: profile.avatar
          },
          recoveryCode,
          sessionToken: session.token,
          expiresAt: session.expires,
          message: "Guest account created"
        }, 201);
      }

      // RECOVER GUEST ACCOUNT
      if (
        path === "/api/guest/recover" &&
        request.method === "POST"
      ) {
        const body = await readBody(request);
        const code = body.recoveryCode;

        if (
          typeof code !== "string" ||
          code.trim().length < 20 ||
          code.trim().length > 100
        ) {
          return json({
            error: "Invalid recovery code"
          }, 400);
        }

        const recoveryHash = await hash(code.trim());

        const user = await env.DB.prepare(`
          SELECT user_id, display_name, avatar
          FROM users
          WHERE recovery_code_hash = ?
        `).bind(recoveryHash).first();

        if (!user) {
          return json({
            error: "Invalid recovery code"
          }, 401);
        }

        const session = await createSession(env, user.user_id);

        return json({
          success: true,
          userId: user.user_id,
          profile: {
            name: user.display_name || "",
            avatar: user.avatar || ""
          },
          sessionToken: session.token,
          expiresAt: session.expires,
          message: "Account recovered"
        });
      }

      // CLOUD SYNC
      if (path === "/api/sync") {
        if (
          request.method !== "GET" &&
          request.method !== "PUT"
        ) {
          return json({
            error: "Method not allowed"
          }, 405);
        }

        const user = await authenticate(request, env);

        if (!user) {
          return json({
            error: "Unauthorized"
          }, 401);
        }

        // RESTORE DATA
        if (request.method === "GET") {
          const data = await env.DB.prepare(`
            SELECT
              ud.core_data,
              ud.addon_data,
              ud.updated_at,
              u.display_name,
              u.avatar
            FROM user_data ud
            JOIN users u ON u.user_id = ud.user_id
            WHERE ud.user_id = ?
          `).bind(user.user_id).first();

          if (!data) {
            return json({
              error: "User data not found"
            }, 404);
          }

          return json({
            success: true,
            coreData: JSON.parse(data.core_data),
            addonData: JSON.parse(data.addon_data),
            profile: {
              name: data.display_name || "",
              avatar: data.avatar || ""
            },
            updatedAt: data.updated_at
          });
        }

        // SAVE DATA
        const body = await readBody(request);

        if (
          !Object.prototype.hasOwnProperty.call(body, "coreData") ||
          !Object.prototype.hasOwnProperty.call(body, "addonData")
        ) {
          return json({
            error: "Missing sync data"
          }, 400);
        }

        const coreData = JSON.stringify(body.coreData);
        const addonData = JSON.stringify(body.addonData);

        // Save study data
        await env.DB.prepare(`
          UPDATE user_data
          SET core_data = ?,
              addon_data = ?,
              updated_at = ?
          WHERE user_id = ?
        `).bind(
          coreData,
          addonData,
          new Date().toISOString(),
          user.user_id
        ).run();

        // Save profile details to users table
        const savedProfile =
          body.profile ||
          (
            body.addonData &&
            typeof body.addonData === "object"
              ? body.addonData.guestProfile
              : null
          );

        if (savedProfile) {
          const profile = validateProfile(
            savedProfile.name,
            savedProfile.avatar
          );

          if (!profile) {
            return json({
              error: "Invalid profile details"
            }, 400);
          }

          await env.DB.prepare(`
            UPDATE users
            SET display_name = ?,
                avatar = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
          `).bind(
            profile.displayName,
            profile.avatar,
            user.user_id
          ).run();
        }

        return json({
          success: true,
          message: "Cloud sync and profile saved"
        });
      }

      return json({
        error: "Endpoint not found"
      }, 404);

    } catch (error) {
      if (error.message === "Payload too large") {
        return json({
          error: "Payload too large"
        }, 413);
      }

      if (
        error instanceof SyntaxError ||
        error.message === "Invalid request body"
      ) {
        return json({
          error: "Invalid JSON"
        }, 400);
      }

      console.error("EduFocus API error:", error);

      return json({
        error: "Internal server error"
      }, 500);
    }
  }
};
