#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as http from "http";
import * as crypto from "crypto";

// Configuration
const API_BASE_URL = process.env.DATABODY_API_URL || "http://localhost:3000";
const CLIENT_ID = "databody-mcp"; // Well-known client ID for the MCP
const CALLBACK_PORT = parseInt(process.env.DATABODY_CALLBACK_PORT || "8787");

// Token storage
const TOKEN_FILE = path.join(os.homedir(), ".databody_token.json");

interface TokenData {
  access_token: string;
  refresh_token?: string;
  expires_at?: number;
}

function loadToken(): TokenData | null {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const data = JSON.parse(fs.readFileSync(TOKEN_FILE, "utf-8"));
      // Check if token is expired
      if (data.expires_at && Date.now() > data.expires_at) {
        // Token expired, try to refresh
        return data.refresh_token ? data : null;
      }
      return data;
    }
  } catch {
    // Ignore errors
  }
  return null;
}

function saveToken(token: TokenData): void {
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(token, null, 2), { mode: 0o600 });
}

function clearToken(): void {
  try {
    fs.unlinkSync(TOKEN_FILE);
  } catch {
    // Ignore errors
  }
}

// PKCE helpers
function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

// OAuth token refresh
async function refreshAccessToken(refreshToken: string): Promise<TokenData | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
      }),
    });

    if (!response.ok) return null;

    const data = await response.json() as {
      access_token: string;
      refresh_token?: string;
      expires_in?: number;
    };

    const token: TokenData = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
    };

    saveToken(token);
    return token;
  } catch {
    return null;
  }
}

// Get valid access token (with refresh if needed)
async function getAccessToken(): Promise<string | null> {
  const token = loadToken();
  if (!token) return null;

  // Check if expired and try to refresh
  if (token.expires_at && Date.now() > token.expires_at) {
    if (token.refresh_token) {
      const refreshed = await refreshAccessToken(token.refresh_token);
      return refreshed?.access_token || null;
    }
    return null;
  }

  return token.access_token;
}

// Helper function for API calls
async function apiCall(
  endpoint: string,
  method: string = "GET",
  body?: object
): Promise<unknown> {
  const accessToken = await getAccessToken();

  if (!accessToken) {
    throw new Error(
      "Not authenticated. Please run the 'authenticate' tool first to login."
    );
  }

  const url = `${API_BASE_URL}/api/v1${endpoint}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
    Authorization: `Bearer ${accessToken}`,
  };

  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (response.status === 401) {
    // Try to refresh token
    const token = loadToken();
    if (token?.refresh_token) {
      const refreshed = await refreshAccessToken(token.refresh_token);
      if (refreshed) {
        // Retry request with new token
        headers.Authorization = `Bearer ${refreshed.access_token}`;
        const retryResponse = await fetch(url, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
        });
        if (retryResponse.ok) {
          return retryResponse.json();
        }
      }
    }
    clearToken();
    throw new Error(
      "Session expired. Please run the 'authenticate' tool to login again."
    );
  }

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`API error (${response.status}): ${error}`);
  }

  return response.json();
}

// OAuth authorization code flow with local callback
async function startOAuthFlow(): Promise<TokenData> {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = crypto.randomBytes(16).toString("hex");

  return new Promise((resolve, reject) => {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url || "", `http://localhost:${CALLBACK_PORT}`);

      if (url.pathname === "/callback") {
        const code = url.searchParams.get("code");
        const returnedState = url.searchParams.get("state");
        const error = url.searchParams.get("error");

        if (error) {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end(`<html><body><h1>Authorization Failed</h1><p>${error}</p></body></html>`);
          server.close();
          reject(new Error(`OAuth error: ${error}`));
          return;
        }

        if (returnedState !== state) {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end("<html><body><h1>Invalid State</h1></body></html>");
          server.close();
          reject(new Error("Invalid OAuth state"));
          return;
        }

        if (!code) {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end("<html><body><h1>No Code Received</h1></body></html>");
          server.close();
          reject(new Error("No authorization code received"));
          return;
        }

        try {
          // Exchange code for token
          const tokenResponse = await fetch(`${API_BASE_URL}/oauth/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "authorization_code",
              code,
              redirect_uri: `http://localhost:${CALLBACK_PORT}/callback`,
              client_id: CLIENT_ID,
              code_verifier: codeVerifier,
            }),
          });

          if (!tokenResponse.ok) {
            const errorText = await tokenResponse.text();
            throw new Error(`Token exchange failed: ${errorText}`);
          }

          const tokenData = await tokenResponse.json() as {
            access_token: string;
            refresh_token?: string;
            expires_in?: number;
          };

          const token: TokenData = {
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token,
            expires_at: tokenData.expires_in
              ? Date.now() + tokenData.expires_in * 1000
              : undefined,
          };

          saveToken(token);

          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(`
            <html>
              <body style="font-family: system-ui; text-align: center; padding: 50px;">
                <h1>Authentication Successful!</h1>
                <p>You can close this window and return to Claude Code.</p>
              </body>
            </html>
          `);

          server.close();
          resolve(token);
        } catch (err) {
          res.writeHead(500, { "Content-Type": "text/html" });
          res.end(`<html><body><h1>Token Exchange Failed</h1><p>${err}</p></body></html>`);
          server.close();
          reject(err);
        }
      } else {
        res.writeHead(404);
        res.end("Not Found");
      }
    });

    server.listen(CALLBACK_PORT, () => {
      const authUrl = new URL(`${API_BASE_URL}/oauth/authorize`);
      authUrl.searchParams.set("client_id", CLIENT_ID);
      authUrl.searchParams.set("redirect_uri", `http://localhost:${CALLBACK_PORT}/callback`);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("scope", "read write");
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("code_challenge", codeChallenge);
      authUrl.searchParams.set("code_challenge_method", "S256");

      console.error(`\nOpen this URL in your browser to authenticate:\n${authUrl.toString()}\n`);
      console.error("Waiting for authentication...");
    });

    server.on("error", (err) => {
      reject(new Error(`Failed to start callback server: ${err.message}`));
    });

    // Timeout after 5 minutes
    setTimeout(() => {
      server.close();
      reject(new Error("Authentication timeout - please try again"));
    }, 5 * 60 * 1000);
  });
}

// Password grant flow (simpler alternative)
async function authenticateWithPassword(
  email: string,
  password: string
): Promise<TokenData> {
  const response = await fetch(`${API_BASE_URL}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password",
      username: email,
      password: password,
      client_id: CLIENT_ID,
      scope: "read write",
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Authentication failed: ${error}`);
  }

  const data = await response.json() as {
    access_token: string;
    refresh_token?: string;
    expires_in?: number;
  };

  const token: TokenData = {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_at: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
  };

  saveToken(token);
  return token;
}

// Define available tools
const tools: Tool[] = [
  // ==================== AUTHENTICATION ====================
  {
    name: "authenticate",
    description:
      "Authenticate with DataBody. Use browser-based OAuth flow (recommended) or provide email/password for direct login.",
    inputSchema: {
      type: "object",
      properties: {
        method: {
          type: "string",
          enum: ["browser", "password"],
          description:
            "Authentication method: 'browser' opens a browser for OAuth, 'password' uses email/password directly",
        },
        email: {
          type: "string",
          description: "Email address (required for password method)",
        },
        password: {
          type: "string",
          description: "Password (required for password method)",
        },
      },
      required: ["method"],
    },
  },
  {
    name: "logout",
    description: "Log out and clear stored authentication tokens",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "auth_status",
    description: "Check current authentication status",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },

  // ==================== USER PROFILE ====================
  {
    name: "get_user_profile",
    description: "Get the current user's profile including email, name, height, sex, birth date, activity level, units, and timezone",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "update_user_profile",
    description: "Update the current user's profile settings",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Display name" },
        height_cm: { type: "number", description: "Height in centimeters" },
        sex: { type: "string", enum: ["male", "female"], description: "Biological sex for TDEE calculations" },
        birth_date: { type: "string", description: "Birth date in YYYY-MM-DD format" },
        activity_level: {
          type: "string",
          enum: ["sedentary", "light", "moderate", "active", "very_active"],
          description: "Activity level for TDEE calculations",
        },
        weight_unit: { type: "string", enum: ["kg", "lbs"], description: "Preferred weight unit" },
        height_unit: { type: "string", enum: ["cm", "ft"], description: "Preferred height unit" },
        timezone: { type: "string", description: "Timezone (e.g., 'America/New_York')" },
      },
      required: [],
    },
  },
  {
    name: "change_password",
    description: "Change the user's password (not available for Apple Sign In accounts)",
    inputSchema: {
      type: "object",
      properties: {
        current_password: { type: "string", description: "Current password" },
        new_password: { type: "string", description: "New password" },
        new_password_confirmation: { type: "string", description: "Confirm new password" },
      },
      required: ["current_password", "new_password", "new_password_confirmation"],
    },
  },
  {
    name: "change_email",
    description: "Change the user's email address. Requires password verification and sends a verification email to the new address.",
    inputSchema: {
      type: "object",
      properties: {
        password: { type: "string", description: "Current password for verification" },
        new_email_address: { type: "string", description: "New email address" },
      },
      required: ["password", "new_email_address"],
    },
  },

  // ==================== HEALTH & SUMMARY ====================
  {
    name: "get_health_summary",
    description:
      "Get the user's health summary including user profile (sex, age, height, activity level), today's macros, goals, latest body stats, recent workouts, and 7-day weight/body fat trends",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "get_health_history",
    description:
      "Get historical health stats (weight, body fat %, sleep, HRV, etc.) for trend analysis. Returns daily snapshots and summary statistics including changes over the period.",
    inputSchema: {
      type: "object",
      properties: {
        days: {
          type: "integer",
          description: "Number of days of history to retrieve (default 30, max 365)",
        },
      },
      required: [],
    },
  },

  // ==================== CHAT THREADS ====================
  {
    name: "list_chat_threads",
    description: "Get all chat threads with message previews, sorted by most recent",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "get_chat_thread",
    description: "Get a specific chat thread with all its messages",
    inputSchema: {
      type: "object",
      properties: {
        thread_id: { type: "integer", description: "ID of the chat thread" },
      },
      required: ["thread_id"],
    },
  },
  {
    name: "create_chat_thread",
    description: "Create a new chat thread",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "Title for the thread (default: 'New Chat')" },
      },
      required: [],
    },
  },
  {
    name: "delete_chat_thread",
    description: "Delete a chat thread and all its messages",
    inputSchema: {
      type: "object",
      properties: {
        thread_id: { type: "integer", description: "ID of the chat thread to delete" },
      },
      required: ["thread_id"],
    },
  },
  {
    name: "generate_thread_title",
    description: "AI-generate a title for a chat thread based on its messages",
    inputSchema: {
      type: "object",
      properties: {
        thread_id: { type: "integer", description: "ID of the chat thread" },
      },
      required: ["thread_id"],
    },
  },

  // ==================== AI FEATURES ====================
  {
    name: "get_chat_history",
    description: "Get chat history for a specific thread or the most recent thread. Also indicates if it's a new day (for greeting).",
    inputSchema: {
      type: "object",
      properties: {
        thread_id: { type: "integer", description: "Optional thread ID (defaults to most recent)" },
      },
      required: [],
    },
  },
  {
    name: "get_token_usage",
    description: "Get AI token usage statistics (total, this month, today) and recent message costs",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "get_daily_greeting",
    description: "Get an AI-generated personalized greeting for today",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "ai_chat",
    description:
      "Chat with the AI nutrition coach. Ask questions about diet, get meal suggestions, or discuss fitness goals. Optionally provide a household_id to include household members' health data for coordinated meal planning.",
    inputSchema: {
      type: "object",
      properties: {
        message: {
          type: "string",
          description: "Message to send to the AI coach",
        },
        thread_id: {
          type: "integer",
          description: "Optional thread ID to continue a conversation",
        },
        household_id: {
          type: "integer",
          description: "Optional household ID to include household context for shared meal planning",
        },
      },
      required: ["message"],
    },
  },
  {
    name: "analyze_photo",
    description: "Analyze a food photo using AI to identify items and estimate macros",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Base64-encoded image data",
        },
        mime_type: {
          type: "string",
          description: "Image MIME type (default: image/jpeg)",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "parse_food_description",
    description: "Parse a text description of food into structured nutrition data",
    inputSchema: {
      type: "object",
      properties: {
        description: {
          type: "string",
          description: "Text description of the food (e.g., '2 eggs with toast and butter')",
        },
      },
      required: ["description"],
    },
  },
  {
    name: "expand_meal_ingredients",
    description: "Expand a meal into individual ingredients with macro breakdowns. Useful for meal suggestions that need itemized logging.",
    inputSchema: {
      type: "object",
      properties: {
        meal_name: {
          type: "string",
          description: "Name of the meal",
        },
        ingredients: {
          type: "string",
          description: "Comma-separated list of ingredients",
        },
        total_macros: {
          type: "object",
          properties: {
            calories: { type: "integer" },
            protein: { type: "number" },
            carbs: { type: "number" },
            fat: { type: "number" },
          },
          description: "Total macros for the meal to distribute among ingredients",
        },
      },
      required: ["meal_name", "ingredients"],
    },
  },
  {
    name: "get_meal_suggestions",
    description:
      "Get AI-powered meal suggestions based on remaining macros and preferences. Optionally provide a household_id to get suggestions that work for all household members.",
    inputSchema: {
      type: "object",
      properties: {
        preferences: {
          type: "string",
          description: "Optional dietary preferences or restrictions",
        },
        household_id: {
          type: "integer",
          description: "Optional household ID to get meal suggestions that consider all household members",
        },
      },
      required: [],
    },
  },

  // ==================== NUTRITION ====================
  {
    name: "get_today_nutrition",
    description:
      "Get all nutrition logs for today, including meals and their items with macro breakdowns",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "get_nutrition_history",
    description: "Get nutrition history for a date range with daily totals and goal comparison",
    inputSchema: {
      type: "object",
      properties: {
        start_date: {
          type: "string",
          description: "Start date in YYYY-MM-DD format (default: 30 days ago)",
        },
        end_date: {
          type: "string",
          description: "End date in YYYY-MM-DD format (default: today)",
        },
      },
      required: [],
    },
  },
  {
    name: "get_nutrition_log",
    description: "Get a specific nutrition log by ID",
    inputSchema: {
      type: "object",
      properties: {
        log_id: { type: "integer", description: "ID of the nutrition log" },
      },
      required: ["log_id"],
    },
  },
  {
    name: "log_food",
    description:
      "Log a food item or meal. Creates a nutrition log entry with the specified foods. IMPORTANT: Always estimate serving_size in grams (e.g., '150g') - never use abstract units like cups, servings, or pieces.",
    inputSchema: {
      type: "object",
      properties: {
        meal_type: {
          type: "string",
          enum: ["breakfast", "lunch", "dinner", "snack"],
          description: "Type of meal",
        },
        items: {
          type: "array",
          description: "Array of food items to log",
          items: {
            type: "object",
            properties: {
              name: { type: "string", description: "Name of the food" },
              brand: { type: "string", description: "Brand name (optional)" },
              serving_size: {
                type: "string",
                description: "Serving size in grams (e.g., '150g', '200g'). ALWAYS estimate weight in grams, never use cups/servings/pieces.",
              },
              serving_quantity: {
                type: "number",
                description: "Number of servings",
              },
              calories: { type: "integer", description: "Calories per serving" },
              protein_grams: { type: "number", description: "Protein in grams" },
              carbs_grams: { type: "number", description: "Carbs in grams" },
              fat_grams: { type: "number", description: "Fat in grams" },
              fiber_grams: { type: "number", description: "Fiber in grams" },
            },
            required: ["name", "calories", "protein_grams", "carbs_grams", "fat_grams"],
          },
        },
        logged_at: {
          type: "string",
          description: "Optional ISO timestamp for when the food was eaten (default: now)",
        },
      },
      required: ["meal_type", "items"],
    },
  },
  {
    name: "update_nutrition_log",
    description: "Update a nutrition log (meal type, time, notes, or items)",
    inputSchema: {
      type: "object",
      properties: {
        log_id: { type: "integer", description: "ID of the nutrition log to update" },
        meal_type: { type: "string", enum: ["breakfast", "lunch", "dinner", "snack"] },
        logged_at: { type: "string", description: "ISO timestamp" },
        notes: { type: "string", description: "Notes about the meal" },
      },
      required: ["log_id"],
    },
  },
  {
    name: "delete_nutrition_log",
    description: "Delete an entire nutrition log and all its items",
    inputSchema: {
      type: "object",
      properties: {
        log_id: { type: "integer", description: "ID of the nutrition log to delete" },
      },
      required: ["log_id"],
    },
  },
  {
    name: "add_nutrition_item",
    description: "Add a food item to an existing nutrition log",
    inputSchema: {
      type: "object",
      properties: {
        log_id: { type: "integer", description: "ID of the nutrition log" },
        name: { type: "string", description: "Name of the food" },
        brand: { type: "string", description: "Brand name (optional)" },
        serving_size: { type: "string", description: "Serving size in grams" },
        serving_quantity: { type: "number", description: "Number of servings" },
        calories: { type: "integer", description: "Calories per serving" },
        protein_grams: { type: "number", description: "Protein in grams" },
        carbs_grams: { type: "number", description: "Carbs in grams" },
        fat_grams: { type: "number", description: "Fat in grams" },
        fiber_grams: { type: "number", description: "Fiber in grams" },
      },
      required: ["log_id", "name", "calories", "protein_grams", "carbs_grams", "fat_grams"],
    },
  },
  {
    name: "delete_nutrition_item",
    description: "Delete a specific food item from a nutrition log",
    inputSchema: {
      type: "object",
      properties: {
        log_id: {
          type: "integer",
          description: "ID of the nutrition log",
        },
        item_id: {
          type: "integer",
          description: "ID of the item to delete",
        },
      },
      required: ["log_id", "item_id"],
    },
  },

  // ==================== FOOD SEARCH & FAVORITES ====================
  {
    name: "search_food",
    description:
      "Search for food items by name to get nutrition information. Returns matching foods with their macros.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Search query for food name",
        },
        source: {
          type: "string",
          enum: ["fatsecret", "usda", "openfoodfacts", "all"],
          description: "Food database to search (default: fatsecret)",
        },
        page: {
          type: "integer",
          description: "Page number (default: 1)",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "get_food_details",
    description: "Get detailed nutrition info for a specific food item including fiber and micronutrients",
    inputSchema: {
      type: "object",
      properties: {
        food_id: {
          type: "string",
          description: "Food ID (e.g., 'fatsecret_12345' or 'usda_12345')",
        },
      },
      required: ["food_id"],
    },
  },
  {
    name: "barcode_lookup",
    description: "Look up a food product by barcode (UPC/EAN)",
    inputSchema: {
      type: "object",
      properties: {
        barcode: {
          type: "string",
          description: "Barcode number",
        },
      },
      required: ["barcode"],
    },
  },
  {
    name: "get_favorites",
    description: "Get the user's favorite foods for quick logging",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "add_favorite",
    description: "Add a food to favorites",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Food name" },
        brand: { type: "string", description: "Brand (optional)" },
        serving_size: { type: "string", description: "Serving size" },
        calories: { type: "integer" },
        protein_grams: { type: "number" },
        carbs_grams: { type: "number" },
        fat_grams: { type: "number" },
        fiber_grams: { type: "number" },
        barcode: { type: "string" },
      },
      required: ["name", "calories", "protein_grams", "carbs_grams", "fat_grams"],
    },
  },
  {
    name: "remove_favorite",
    description: "Remove a food from favorites",
    inputSchema: {
      type: "object",
      properties: {
        favorite_id: { type: "integer", description: "ID of the favorite to remove" },
      },
      required: ["favorite_id"],
    },
  },
  {
    name: "get_recents",
    description: "Get recently logged foods",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },

  // ==================== GOALS ====================
  {
    name: "get_current_goal",
    description:
      "Get the user's current active fitness goal including calorie and macro targets",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "list_goals",
    description: "Get all goals (active and inactive) sorted by most recent",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "get_goal",
    description: "Get a specific goal by ID",
    inputSchema: {
      type: "object",
      properties: {
        goal_id: { type: "integer", description: "ID of the goal" },
      },
      required: ["goal_id"],
    },
  },
  {
    name: "create_goal",
    description: "Create a new fitness goal with target body composition and macro targets",
    inputSchema: {
      type: "object",
      properties: {
        target_body_fat_percentage: {
          type: "number",
          description: "Target body fat percentage",
        },
        target_date: {
          type: "string",
          description: "Target date in YYYY-MM-DD format",
        },
        daily_calorie_target: {
          type: "integer",
          description: "Daily calorie target",
        },
        daily_protein_grams: {
          type: "integer",
          description: "Daily protein target in grams",
        },
        daily_carbs_grams: {
          type: "integer",
          description: "Daily carbs target in grams",
        },
        daily_fat_grams: {
          type: "integer",
          description: "Daily fat target in grams",
        },
        strategy: {
          type: "string",
          enum: ["cut", "maintain", "bulk"],
          description: "Goal strategy",
        },
        active: {
          type: "boolean",
          description: "Set as active goal (default: true)",
        },
      },
      required: ["daily_calorie_target", "daily_protein_grams", "daily_carbs_grams", "daily_fat_grams"],
    },
  },
  {
    name: "update_goal",
    description: "Update an existing goal's settings",
    inputSchema: {
      type: "object",
      properties: {
        goal_id: { type: "integer", description: "ID of the goal to update" },
        target_body_fat_percentage: { type: "number" },
        target_date: { type: "string" },
        daily_calorie_target: { type: "integer" },
        daily_protein_grams: { type: "integer" },
        daily_carbs_grams: { type: "integer" },
        daily_fat_grams: { type: "integer" },
        strategy: { type: "string", enum: ["cut", "maintain", "bulk"] },
        active: { type: "boolean" },
        protein_per_lb_lbm: { type: "number", description: "Protein grams per lb of lean body mass" },
        fat_per_lb: { type: "number", description: "Fat grams per lb of body weight" },
        weekly_weight_loss_percentage: { type: "number", description: "Target weekly weight loss %" },
        flexible_weekends_enabled: { type: "boolean" },
        flexible_weekends_percentage: { type: "integer", description: "Extra calories on weekends %" },
      },
      required: ["goal_id"],
    },
  },
  {
    name: "delete_goal",
    description: "Delete a goal",
    inputSchema: {
      type: "object",
      properties: {
        goal_id: { type: "integer", description: "ID of the goal to delete" },
      },
      required: ["goal_id"],
    },
  },
  {
    name: "calculate_goal",
    description: "Recalculate a goal's macro targets based on current health data (weight, body fat, TDEE)",
    inputSchema: {
      type: "object",
      properties: {
        goal_id: { type: "integer", description: "ID of the goal to recalculate" },
      },
      required: ["goal_id"],
    },
  },

  // ==================== WORKOUTS ====================
  {
    name: "get_recent_workouts",
    description: "Get the user's recent workout logs (last 7 days) with summary stats",
    inputSchema: {
      type: "object",
      properties: {
        limit: {
          type: "integer",
          description: "Number of workouts to return (default 10)",
        },
      },
      required: [],
    },
  },
  {
    name: "list_workouts",
    description: "Get workouts with optional filtering by date range and type",
    inputSchema: {
      type: "object",
      properties: {
        start_date: { type: "string", description: "Start date (YYYY-MM-DD)" },
        end_date: { type: "string", description: "End date (YYYY-MM-DD)" },
        type: { type: "string", description: "Filter by workout type" },
        limit: { type: "integer", description: "Max results (default 50)" },
      },
      required: [],
    },
  },
  {
    name: "get_workout",
    description: "Get a specific workout by ID",
    inputSchema: {
      type: "object",
      properties: {
        workout_id: { type: "integer", description: "ID of the workout" },
      },
      required: ["workout_id"],
    },
  },
  {
    name: "create_workout",
    description: "Log a new workout",
    inputSchema: {
      type: "object",
      properties: {
        workout_type: { type: "string", description: "Type of workout (e.g., 'running', 'cycling', 'strength')" },
        started_at: { type: "string", description: "Start time (ISO format)" },
        ended_at: { type: "string", description: "End time (ISO format)" },
        duration_minutes: { type: "integer", description: "Duration in minutes" },
        calories_burned: { type: "integer", description: "Calories burned" },
        average_heart_rate: { type: "integer", description: "Average heart rate" },
        distance_meters: { type: "number", description: "Distance in meters" },
      },
      required: ["workout_type", "started_at", "duration_minutes"],
    },
  },
  {
    name: "update_workout",
    description: "Update a workout",
    inputSchema: {
      type: "object",
      properties: {
        workout_id: { type: "integer", description: "ID of the workout to update" },
        workout_type: { type: "string" },
        started_at: { type: "string" },
        ended_at: { type: "string" },
        duration_minutes: { type: "integer" },
        calories_burned: { type: "integer" },
        average_heart_rate: { type: "integer" },
        distance_meters: { type: "number" },
      },
      required: ["workout_id"],
    },
  },
  {
    name: "delete_workout",
    description: "Delete a workout",
    inputSchema: {
      type: "object",
      properties: {
        workout_id: { type: "integer", description: "ID of the workout to delete" },
      },
      required: ["workout_id"],
    },
  },

  // ==================== NOTES ====================
  {
    name: "get_notes",
    description:
      "Get the user's personal notes. These notes contain preferences, equipment, dietary needs, and other information the user wants the AI coach to know.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "create_note",
    description:
      "Create a personal note for the user. Use this to save user preferences, equipment they have, dietary restrictions, or anything they want the AI coach to remember.",
    inputSchema: {
      type: "object",
      properties: {
        content: {
          type: "string",
          description: "The content of the note",
        },
      },
      required: ["content"],
    },
  },
  {
    name: "update_note",
    description: "Update an existing note",
    inputSchema: {
      type: "object",
      properties: {
        note_id: { type: "integer", description: "ID of the note to update" },
        content: { type: "string", description: "New content for the note" },
      },
      required: ["note_id", "content"],
    },
  },
  {
    name: "delete_note",
    description: "Delete a personal note by ID",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "integer",
          description: "ID of the note to delete",
        },
      },
      required: ["id"],
    },
  },

  // ==================== HOUSEHOLDS ====================
  {
    name: "get_households",
    description:
      "Get all households the user belongs to. Households allow sharing health data with family members for coordinated meal planning.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "get_household_summary",
    description:
      "Get detailed information about a specific household including all members' health data (goals, stats, notes, intake, nutrition logs) for coordinated meal suggestions. Use the 'days' parameter to see what foods have been eaten recently to suggest variety.",
    inputSchema: {
      type: "object",
      properties: {
        household_id: {
          type: "integer",
          description: "ID of the household to get details for",
        },
        days: {
          type: "integer",
          description: "Number of days of nutrition history to include (1-30, default 1 for today only). Use 7 to see the past week's meals for variety suggestions.",
        },
      },
      required: ["household_id"],
    },
  },
  {
    name: "create_household",
    description: "Create a new household",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Name of the household" },
      },
      required: ["name"],
    },
  },
  {
    name: "update_household",
    description: "Update a household's name",
    inputSchema: {
      type: "object",
      properties: {
        household_id: { type: "integer", description: "ID of the household" },
        name: { type: "string", description: "New name for the household" },
      },
      required: ["household_id", "name"],
    },
  },
  {
    name: "delete_household",
    description: "Delete a household (owner only)",
    inputSchema: {
      type: "object",
      properties: {
        household_id: { type: "integer", description: "ID of the household to delete" },
      },
      required: ["household_id"],
    },
  },
  {
    name: "leave_household",
    description: "Leave a household (non-owners only)",
    inputSchema: {
      type: "object",
      properties: {
        household_id: { type: "integer", description: "ID of the household to leave" },
      },
      required: ["household_id"],
    },
  },
  {
    name: "list_household_members",
    description: "List all members of a household",
    inputSchema: {
      type: "object",
      properties: {
        household_id: { type: "integer", description: "ID of the household" },
      },
      required: ["household_id"],
    },
  },
  {
    name: "remove_household_member",
    description: "Remove a member from a household (owner only)",
    inputSchema: {
      type: "object",
      properties: {
        household_id: { type: "integer", description: "ID of the household" },
        member_id: { type: "integer", description: "ID of the member to remove" },
      },
      required: ["household_id", "member_id"],
    },
  },

  // ==================== HOUSEHOLD INVITES ====================
  {
    name: "list_household_invites",
    description: "List pending invites for a household (owner view)",
    inputSchema: {
      type: "object",
      properties: {
        household_id: { type: "integer", description: "ID of the household" },
      },
      required: ["household_id"],
    },
  },
  {
    name: "list_pending_invites",
    description: "List invites sent to the current user that are pending acceptance",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "create_household_invite",
    description: "Invite someone to join a household by email (owner only). Sends an invitation email.",
    inputSchema: {
      type: "object",
      properties: {
        household_id: { type: "integer", description: "ID of the household" },
        email: { type: "string", description: "Email address to invite" },
      },
      required: ["household_id", "email"],
    },
  },
  {
    name: "cancel_household_invite",
    description: "Cancel a pending household invite (owner only)",
    inputSchema: {
      type: "object",
      properties: {
        household_id: { type: "integer", description: "ID of the household" },
        invite_id: { type: "integer", description: "ID of the invite to cancel" },
      },
      required: ["household_id", "invite_id"],
    },
  },
  {
    name: "accept_invite",
    description: "Accept a household invitation sent to you",
    inputSchema: {
      type: "object",
      properties: {
        invite_id: { type: "integer", description: "ID of the invite to accept" },
      },
      required: ["invite_id"],
    },
  },
  {
    name: "decline_invite",
    description: "Decline a household invitation",
    inputSchema: {
      type: "object",
      properties: {
        invite_id: { type: "integer", description: "ID of the invite to decline" },
      },
      required: ["invite_id"],
    },
  },
  {
    name: "accept_invite_by_token",
    description: "Accept a household invitation using the email token",
    inputSchema: {
      type: "object",
      properties: {
        token: { type: "string", description: "Invitation token from the email link" },
      },
      required: ["token"],
    },
  },

  // ==================== MEAL SUGGESTIONS FOR HOUSEHOLD ====================
  {
    name: "suggest_meal_to_member",
    description:
      "Create a pending food log for another household member. They will see it as a suggestion and can accept or decline. Use this for shared meals where one person logs for everyone.",
    inputSchema: {
      type: "object",
      properties: {
        household_id: {
          type: "integer",
          description: "ID of the household",
        },
        user_id: {
          type: "integer",
          description: "ID of the household member to suggest the meal to",
        },
        meal_type: {
          type: "string",
          enum: ["breakfast", "lunch", "dinner", "snack"],
          description: "Type of meal",
        },
        items: {
          type: "array",
          description: "Array of food items to suggest",
          items: {
            type: "object",
            properties: {
              name: { type: "string", description: "Name of the food" },
              brand: { type: "string", description: "Brand name (optional)" },
              serving_size: { type: "string", description: "Serving size description" },
              serving_quantity: { type: "number", description: "Number of servings" },
              calories: { type: "integer", description: "Calories per serving" },
              protein_grams: { type: "number", description: "Protein in grams" },
              carbs_grams: { type: "number", description: "Carbs in grams" },
              fat_grams: { type: "number", description: "Fat in grams" },
              fiber_grams: { type: "number", description: "Fiber in grams" },
            },
            required: ["name", "calories", "protein_grams", "carbs_grams", "fat_grams"],
          },
        },
        notes: {
          type: "string",
          description: "Optional note about the meal (e.g., 'We had this for dinner together')",
        },
      },
      required: ["household_id", "user_id", "meal_type", "items"],
    },
  },
];

// Tool handlers
async function handleTool(
  name: string,
  args: Record<string, unknown>
): Promise<string> {
  switch (name) {
    // ==================== AUTHENTICATION ====================
    case "authenticate": {
      const method = args.method as string;

      if (method === "browser") {
        try {
          await startOAuthFlow();
          return JSON.stringify({
            success: true,
            message: "Successfully authenticated with DataBody!",
          });
        } catch (err) {
          return JSON.stringify({
            error: `Authentication failed: ${err instanceof Error ? err.message : String(err)}`,
          });
        }
      } else if (method === "password") {
        const email = args.email as string;
        const password = args.password as string;

        if (!email || !password) {
          return JSON.stringify({
            error: "Email and password are required for password authentication",
          });
        }

        try {
          await authenticateWithPassword(email, password);
          return JSON.stringify({
            success: true,
            message: "Successfully authenticated with DataBody!",
          });
        } catch (err) {
          return JSON.stringify({
            error: `Authentication failed: ${err instanceof Error ? err.message : String(err)}`,
          });
        }
      } else {
        return JSON.stringify({ error: "Invalid authentication method" });
      }
    }

    case "logout": {
      clearToken();
      return JSON.stringify({
        success: true,
        message: "Successfully logged out",
      });
    }

    case "auth_status": {
      const token = await getAccessToken();
      if (token) {
        return JSON.stringify({
          authenticated: true,
          message: "You are logged in to DataBody",
        });
      } else {
        return JSON.stringify({
          authenticated: false,
          message: "Not authenticated. Use the 'authenticate' tool to login.",
        });
      }
    }

    // ==================== USER PROFILE ====================
    case "get_user_profile": {
      const result = await apiCall("/users/me");
      return JSON.stringify(result, null, 2);
    }

    case "update_user_profile": {
      const updateParams: Record<string, unknown> = {};
      const fields = ["name", "height_cm", "sex", "birth_date", "activity_level", "weight_unit", "height_unit", "timezone"];
      for (const field of fields) {
        if (args[field] !== undefined) {
          updateParams[field] = args[field];
        }
      }
      const result = await apiCall("/users/me", "PATCH", updateParams);
      return JSON.stringify(result, null, 2);
    }

    case "change_password": {
      const result = await apiCall("/users/me/change_password", "POST", {
        current_password: args.current_password,
        new_password: args.new_password,
        new_password_confirmation: args.new_password_confirmation,
      });
      return JSON.stringify(result, null, 2);
    }

    case "change_email": {
      const result = await apiCall("/users/me/change_email", "POST", {
        password: args.password,
        new_email_address: args.new_email_address,
      });
      return JSON.stringify(result, null, 2);
    }

    // ==================== HEALTH & SUMMARY ====================
    case "get_health_summary": {
      const result = await apiCall("/health/summary");
      return JSON.stringify(result, null, 2);
    }

    case "get_health_history": {
      const days = (args.days as number) || 30;
      const result = await apiCall(`/health/history?days=${days}`);
      return JSON.stringify(result, null, 2);
    }

    // ==================== CHAT THREADS ====================
    case "list_chat_threads": {
      const result = await apiCall("/chat_threads");
      return JSON.stringify(result, null, 2);
    }

    case "get_chat_thread": {
      const result = await apiCall(`/chat_threads/${args.thread_id}`);
      return JSON.stringify(result, null, 2);
    }

    case "create_chat_thread": {
      const result = await apiCall("/chat_threads", "POST", {
        title: args.title || "New Chat",
      });
      return JSON.stringify(result, null, 2);
    }

    case "delete_chat_thread": {
      await apiCall(`/chat_threads/${args.thread_id}`, "DELETE");
      return JSON.stringify({ success: true, message: "Thread deleted" });
    }

    case "generate_thread_title": {
      const result = await apiCall(`/chat_threads/${args.thread_id}/generate_title`, "POST");
      return JSON.stringify(result, null, 2);
    }

    // ==================== AI FEATURES ====================
    case "get_chat_history": {
      const params = args.thread_id ? `?thread_id=${args.thread_id}` : "";
      const result = await apiCall(`/ai/chat_history${params}`);
      return JSON.stringify(result, null, 2);
    }

    case "get_token_usage": {
      const result = await apiCall("/ai/token_usage");
      return JSON.stringify(result, null, 2);
    }

    case "get_daily_greeting": {
      const result = await apiCall("/ai/daily_greeting");
      return JSON.stringify(result, null, 2);
    }

    case "ai_chat": {
      const body: Record<string, unknown> = { message: args.message };
      if (args.thread_id) {
        body.thread_id = args.thread_id;
      }
      if (args.household_id) {
        body.household_id = args.household_id;
      }
      const result = await apiCall("/ai/chat", "POST", body);
      return JSON.stringify(result, null, 2);
    }

    case "analyze_photo": {
      const result = await apiCall("/ai/analyze_photo", "POST", {
        image: args.image,
        mime_type: args.mime_type || "image/jpeg",
      });
      return JSON.stringify(result, null, 2);
    }

    case "parse_food_description": {
      const result = await apiCall("/ai/parse_description", "POST", {
        description: args.description,
      });
      return JSON.stringify(result, null, 2);
    }

    case "expand_meal_ingredients": {
      const result = await apiCall("/ai/expand_meal_ingredients", "POST", {
        meal_name: args.meal_name,
        ingredients: args.ingredients,
        total_macros: args.total_macros,
      });
      return JSON.stringify(result, null, 2);
    }

    case "get_meal_suggestions": {
      const queryParams: string[] = [];
      if (args.preferences) {
        queryParams.push(`preferences=${encodeURIComponent(args.preferences as string)}`);
      }
      if (args.household_id) {
        queryParams.push(`household_id=${args.household_id}`);
      }
      const params = queryParams.length > 0 ? `?${queryParams.join("&")}` : "";
      const result = await apiCall(`/ai/suggestions${params}`);
      return JSON.stringify(result, null, 2);
    }

    // ==================== NUTRITION ====================
    case "get_today_nutrition": {
      const result = await apiCall("/nutrition/today");
      return JSON.stringify(result, null, 2);
    }

    case "get_nutrition_history": {
      const queryParams: string[] = [];
      if (args.start_date) {
        queryParams.push(`start_date=${args.start_date}`);
      }
      if (args.end_date) {
        queryParams.push(`end_date=${args.end_date}`);
      }
      const params = queryParams.length > 0 ? `?${queryParams.join("&")}` : "";
      const result = await apiCall(`/nutrition/history${params}`);
      return JSON.stringify(result, null, 2);
    }

    case "get_nutrition_log": {
      const result = await apiCall(`/nutrition/${args.log_id}`);
      return JSON.stringify(result, null, 2);
    }

    case "log_food": {
      const items = args.items as Array<{
        name: string;
        brand?: string;
        serving_size?: string;
        serving_quantity?: number;
        calories: number;
        protein_grams: number;
        carbs_grams: number;
        fat_grams: number;
        fiber_grams?: number;
      }>;

      const result = await apiCall("/nutrition", "POST", {
        meal_type: args.meal_type,
        logged_at: args.logged_at || new Date().toISOString(),
        nutrition_items_attributes: items.map((item) => ({
          name: item.name,
          brand: item.brand,
          serving_size: item.serving_size,
          serving_quantity: item.serving_quantity || 1,
          calories: item.calories,
          protein_grams: item.protein_grams,
          carbs_grams: item.carbs_grams,
          fat_grams: item.fat_grams,
          fiber_grams: item.fiber_grams || 0,
        })),
      });
      return JSON.stringify(result, null, 2);
    }

    case "update_nutrition_log": {
      const updateParams: Record<string, unknown> = {};
      if (args.meal_type) updateParams.meal_type = args.meal_type;
      if (args.logged_at) updateParams.logged_at = args.logged_at;
      if (args.notes !== undefined) updateParams.notes = args.notes;

      const result = await apiCall(`/nutrition/${args.log_id}`, "PATCH", updateParams);
      return JSON.stringify(result, null, 2);
    }

    case "delete_nutrition_log": {
      await apiCall(`/nutrition/${args.log_id}`, "DELETE");
      return JSON.stringify({ success: true, message: "Nutrition log deleted" });
    }

    case "add_nutrition_item": {
      const result = await apiCall(`/nutrition/${args.log_id}/items`, "POST", {
        name: args.name,
        brand: args.brand,
        serving_size: args.serving_size,
        serving_quantity: args.serving_quantity || 1,
        calories: args.calories,
        protein_grams: args.protein_grams,
        carbs_grams: args.carbs_grams,
        fat_grams: args.fat_grams,
        fiber_grams: args.fiber_grams || 0,
      });
      return JSON.stringify(result, null, 2);
    }

    case "delete_nutrition_item": {
      await apiCall(
        `/nutrition/${args.log_id}/items/${args.item_id}`,
        "DELETE"
      );
      return JSON.stringify({ success: true, message: "Item deleted" });
    }

    // ==================== FOOD SEARCH & FAVORITES ====================
    case "search_food": {
      const queryParams = [`q=${encodeURIComponent(args.query as string)}`];
      if (args.source) queryParams.push(`source=${args.source}`);
      if (args.page) queryParams.push(`page=${args.page}`);
      const result = await apiCall(`/foods/search?${queryParams.join("&")}`);
      return JSON.stringify(result, null, 2);
    }

    case "get_food_details": {
      const result = await apiCall(`/foods/details/${encodeURIComponent(args.food_id as string)}`);
      return JSON.stringify(result, null, 2);
    }

    case "barcode_lookup": {
      const result = await apiCall(`/foods/barcode/${encodeURIComponent(args.barcode as string)}`);
      return JSON.stringify(result, null, 2);
    }

    case "get_favorites": {
      const result = await apiCall("/foods/favorites");
      return JSON.stringify(result, null, 2);
    }

    case "add_favorite": {
      const result = await apiCall("/foods/favorites", "POST", {
        name: args.name,
        brand: args.brand,
        serving_size: args.serving_size,
        calories: args.calories,
        protein_grams: args.protein_grams,
        carbs_grams: args.carbs_grams,
        fat_grams: args.fat_grams,
        fiber_grams: args.fiber_grams,
        barcode: args.barcode,
      });
      return JSON.stringify(result, null, 2);
    }

    case "remove_favorite": {
      await apiCall(`/foods/favorites/${args.favorite_id}`, "DELETE");
      return JSON.stringify({ success: true, message: "Favorite removed" });
    }

    case "get_recents": {
      const result = await apiCall("/foods/recents");
      return JSON.stringify(result, null, 2);
    }

    // ==================== GOALS ====================
    case "get_current_goal": {
      const result = await apiCall("/goals/current");
      return JSON.stringify(result, null, 2);
    }

    case "list_goals": {
      const result = await apiCall("/goals");
      return JSON.stringify(result, null, 2);
    }

    case "get_goal": {
      const result = await apiCall(`/goals/${args.goal_id}`);
      return JSON.stringify(result, null, 2);
    }

    case "create_goal": {
      const result = await apiCall("/goals", "POST", {
        target_body_fat_percentage: args.target_body_fat_percentage,
        target_date: args.target_date,
        daily_calorie_target: args.daily_calorie_target,
        daily_protein_grams: args.daily_protein_grams,
        daily_carbs_grams: args.daily_carbs_grams,
        daily_fat_grams: args.daily_fat_grams,
        strategy: args.strategy || "maintain",
        active: args.active !== false,
      });
      return JSON.stringify(result, null, 2);
    }

    case "update_goal": {
      const updateParams: Record<string, unknown> = {};
      const fields = [
        "target_body_fat_percentage", "target_date", "daily_calorie_target",
        "daily_protein_grams", "daily_carbs_grams", "daily_fat_grams",
        "strategy", "active", "protein_per_lb_lbm", "fat_per_lb",
        "weekly_weight_loss_percentage", "flexible_weekends_enabled", "flexible_weekends_percentage"
      ];
      for (const field of fields) {
        if (args[field] !== undefined) {
          updateParams[field] = args[field];
        }
      }
      const result = await apiCall(`/goals/${args.goal_id}`, "PATCH", updateParams);
      return JSON.stringify(result, null, 2);
    }

    case "delete_goal": {
      await apiCall(`/goals/${args.goal_id}`, "DELETE");
      return JSON.stringify({ success: true, message: "Goal deleted" });
    }

    case "calculate_goal": {
      const result = await apiCall(`/goals/${args.goal_id}/calculate`, "POST");
      return JSON.stringify(result, null, 2);
    }

    // ==================== WORKOUTS ====================
    case "get_recent_workouts": {
      const limit = (args.limit as number) || 10;
      const result = await apiCall(`/workouts/recent?limit=${limit}`);
      return JSON.stringify(result, null, 2);
    }

    case "list_workouts": {
      const queryParams: string[] = [];
      if (args.start_date) queryParams.push(`start_date=${args.start_date}`);
      if (args.end_date) queryParams.push(`end_date=${args.end_date}`);
      if (args.type) queryParams.push(`type=${encodeURIComponent(args.type as string)}`);
      if (args.limit) queryParams.push(`limit=${args.limit}`);
      const params = queryParams.length > 0 ? `?${queryParams.join("&")}` : "";
      const result = await apiCall(`/workouts${params}`);
      return JSON.stringify(result, null, 2);
    }

    case "get_workout": {
      const result = await apiCall(`/workouts/${args.workout_id}`);
      return JSON.stringify(result, null, 2);
    }

    case "create_workout": {
      const result = await apiCall("/workouts", "POST", {
        workout_type: args.workout_type,
        started_at: args.started_at,
        ended_at: args.ended_at,
        duration_minutes: args.duration_minutes,
        calories_burned: args.calories_burned,
        average_heart_rate: args.average_heart_rate,
        distance_meters: args.distance_meters,
      });
      return JSON.stringify(result, null, 2);
    }

    case "update_workout": {
      const updateParams: Record<string, unknown> = {};
      const fields = ["workout_type", "started_at", "ended_at", "duration_minutes", "calories_burned", "average_heart_rate", "distance_meters"];
      for (const field of fields) {
        if (args[field] !== undefined) {
          updateParams[field] = args[field];
        }
      }
      const result = await apiCall(`/workouts/${args.workout_id}`, "PATCH", updateParams);
      return JSON.stringify(result, null, 2);
    }

    case "delete_workout": {
      await apiCall(`/workouts/${args.workout_id}`, "DELETE");
      return JSON.stringify({ success: true, message: "Workout deleted" });
    }

    // ==================== NOTES ====================
    case "get_notes": {
      const result = await apiCall("/notes");
      return JSON.stringify(result, null, 2);
    }

    case "create_note": {
      const result = await apiCall("/notes", "POST", {
        content: args.content,
        created_via: "mcp",
      });
      return JSON.stringify(result, null, 2);
    }

    case "update_note": {
      const result = await apiCall(`/notes/${args.note_id}`, "PATCH", {
        content: args.content,
      });
      return JSON.stringify(result, null, 2);
    }

    case "delete_note": {
      await apiCall(`/notes/${args.id}`, "DELETE");
      return JSON.stringify({ success: true, message: "Note deleted" });
    }

    // ==================== HOUSEHOLDS ====================
    case "get_households": {
      const result = await apiCall("/households");
      return JSON.stringify(result, null, 2);
    }

    case "get_household_summary": {
      let url = `/households/${args.household_id}?include_health=true`;
      if (args.days) {
        url += `&days=${args.days}`;
      }
      const result = await apiCall(url);
      return JSON.stringify(result, null, 2);
    }

    case "create_household": {
      const result = await apiCall("/households", "POST", {
        name: args.name,
      });
      return JSON.stringify(result, null, 2);
    }

    case "update_household": {
      const result = await apiCall(`/households/${args.household_id}`, "PATCH", {
        name: args.name,
      });
      return JSON.stringify(result, null, 2);
    }

    case "delete_household": {
      await apiCall(`/households/${args.household_id}`, "DELETE");
      return JSON.stringify({ success: true, message: "Household deleted" });
    }

    case "leave_household": {
      await apiCall(`/households/${args.household_id}/leave`, "DELETE");
      return JSON.stringify({ success: true, message: "Left household" });
    }

    case "list_household_members": {
      const result = await apiCall(`/households/${args.household_id}/members`);
      return JSON.stringify(result, null, 2);
    }

    case "remove_household_member": {
      await apiCall(`/households/${args.household_id}/members/${args.member_id}`, "DELETE");
      return JSON.stringify({ success: true, message: "Member removed" });
    }

    // ==================== HOUSEHOLD INVITES ====================
    case "list_household_invites": {
      const result = await apiCall(`/households/${args.household_id}/invites`);
      return JSON.stringify(result, null, 2);
    }

    case "list_pending_invites": {
      const result = await apiCall("/household_invites");
      return JSON.stringify(result, null, 2);
    }

    case "create_household_invite": {
      const result = await apiCall(`/households/${args.household_id}/invites`, "POST", {
        email: args.email,
      });
      return JSON.stringify(result, null, 2);
    }

    case "cancel_household_invite": {
      await apiCall(`/households/${args.household_id}/invites/${args.invite_id}`, "DELETE");
      return JSON.stringify({ success: true, message: "Invite cancelled" });
    }

    case "accept_invite": {
      const result = await apiCall(`/household_invites/${args.invite_id}/accept`, "POST");
      return JSON.stringify(result, null, 2);
    }

    case "decline_invite": {
      const result = await apiCall(`/household_invites/${args.invite_id}/decline`, "POST");
      return JSON.stringify(result, null, 2);
    }

    case "accept_invite_by_token": {
      const result = await apiCall("/household_invites/accept_by_token", "POST", {
        token: args.token,
      });
      return JSON.stringify(result, null, 2);
    }

    // ==================== MEAL SUGGESTIONS FOR HOUSEHOLD ====================
    case "suggest_meal_to_member": {
      const items = args.items as Array<{
        name: string;
        brand?: string;
        serving_size?: string;
        serving_quantity?: number;
        calories: number;
        protein_grams: number;
        carbs_grams: number;
        fat_grams: number;
        fiber_grams?: number;
      }>;

      const result = await apiCall(
        `/households/${args.household_id}/pending_logs`,
        "POST",
        {
          user_id: args.user_id,
          meal_type: args.meal_type,
          notes: args.notes,
          logged_at: new Date().toISOString(),
          items: items.map((item) => ({
            name: item.name,
            brand: item.brand,
            serving_size: item.serving_size,
            serving_quantity: item.serving_quantity || 1,
            calories: item.calories,
            protein_grams: item.protein_grams,
            carbs_grams: item.carbs_grams,
            fat_grams: item.fat_grams,
            fiber_grams: item.fiber_grams || 0,
          })),
        }
      );
      return JSON.stringify(result, null, 2);
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// Create and start the server
const server = new Server(
  {
    name: "databody-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register handlers
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    const result = await handleTool(name, (args as Record<string, unknown>) || {});
    return {
      content: [{ type: "text", text: result }],
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error: ${message}` }],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("DataBody MCP server started");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
