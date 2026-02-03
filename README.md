# DataBody MCP Server

An MCP (Model Context Protocol) server that allows Claude to interact with your DataBody health tracking data using secure OAuth authentication.

## Features

The MCP server provides 60+ tools for:

- **Authentication** - Secure OAuth2 login with PKCE support
- **Health Summary** - Get your daily macros, goals, body stats, and recent workouts
- **Nutrition Logging** - Log food items with full macro tracking
- **Food Search** - Search foods, barcodes, favorites, and recents
- **Goal Management** - Create and manage fitness goals with auto-calculation
- **AI Coach** - Chat with the AI nutrition coach
- **Meal Suggestions** - Get AI-powered meal suggestions based on remaining macros
- **Photo Analysis** - Analyze food photos to estimate macros
- **Workout Tracking** - Log and view workout history
- **Notes & Memory** - Save preferences and dietary restrictions
- **Households** - Share data with family for coordinated meal planning
- **Chat Threads** - Manage conversation history with the AI coach

## Installation

Choose one of these installation methods:

### Option A: Download MCPB Bundle (Recommended)

The easiest option. Download a single file that contains everything pre-bundled. No npm or Node.js required.

1. Download the latest `.mcpb` file from [GitHub Releases](https://github.com/databody-ai/databody-mcp/releases/latest)
2. Double-click the file or drag it onto Claude Desktop
3. Done! The server is installed and configured automatically.

### Option B: Install via npm

If you have Node.js 20+ installed:

```bash
npm install -g @databody/mcp
```

### Option C: Build from Source

For developers who want to customize or contribute:

```bash
# Clone the repository
git clone https://github.com/databody-ai/databody-mcp.git
cd databody-mcp

# Install dependencies and build
npm install
npm run build
```

## Configuration

### If you installed via MCPB

No manual configuration needed! The server is configured automatically when you install the `.mcpb` file.

### If you installed via npm or source

Add to your Claude Desktop config file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

**For npm install:**
```json
{
  "mcpServers": {
    "databody": {
      "command": "npx",
      "args": ["-y", "@databody/mcp"],
      "env": {
        "DATABODY_API_URL": "https://databody.ai"
      }
    }
  }
}
```

**For source install:**
```json
{
  "mcpServers": {
    "databody": {
      "command": "node",
      "args": ["/path/to/databody-mcp/dist/index.js"],
      "env": {
        "DATABODY_API_URL": "https://databody.ai"
      }
    }
  }
}
```

Replace `/path/to/databody-mcp` with the actual path where you cloned the repository.

## Authentication

When you first use a DataBody tool, you'll need to authenticate. Use the `authenticate` tool:

**Browser-based OAuth (recommended):**
```
Use the authenticate tool with method "browser"
```

This will:
1. Start a local callback server on port 8787
2. Display a URL to open in your browser
3. After you log in and authorize, the token is saved automatically

**Password-based (alternative):**
```
Use the authenticate tool with method "password", email "your@email.com", and password "yourpassword"
```

Tokens are stored securely in `~/.databody_token.json` with restricted permissions.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABODY_API_URL` | URL of your DataBody API | `https://databody.ai` |
| `DATABODY_CALLBACK_PORT` | Port for OAuth callback server | `8787` |

## Available Tools

### Authentication
- `authenticate` - Login via browser OAuth or password
- `logout` - Clear stored tokens
- `auth_status` - Check login status

### User Profile
- `get_user_profile` - Get profile settings
- `update_user_profile` - Update name, height, activity level, etc.
- `change_password` / `change_email` - Account management

### Health & Summary
- `get_health_summary` - Dashboard with macros, goals, stats, workouts
- `get_health_history` - Historical trends for weight, body fat, etc.

### Nutrition
- `get_today_nutrition` - Today's food logs
- `get_nutrition_history` - Date range history
- `log_food` - Log meals with macro tracking
- `update_nutrition_log` / `delete_nutrition_log` - Manage logs
- `add_nutrition_item` / `delete_nutrition_item` - Manage items

### Food Search
- `search_food` - Search FatSecret, USDA, OpenFoodFacts
- `get_food_details` - Detailed nutrition info
- `barcode_lookup` - Scan product barcodes
- `get_favorites` / `add_favorite` / `remove_favorite` - Manage favorites
- `get_recents` - Recently logged foods

### AI Features
- `ai_chat` - Chat with the nutrition coach
- `get_meal_suggestions` - AI meal recommendations
- `analyze_photo` - Identify foods from photos
- `parse_food_description` - Parse text to structured data
- `expand_meal_ingredients` - Break meals into ingredients
- `get_daily_greeting` - Personalized daily greeting
- `get_token_usage` - AI usage statistics

### Chat Threads
- `list_chat_threads` / `get_chat_thread` - View conversations
- `create_chat_thread` / `delete_chat_thread` - Manage threads
- `generate_thread_title` - AI-generate thread titles
- `get_chat_history` - Get messages for a thread

### Goals
- `get_current_goal` / `list_goals` / `get_goal` - View goals
- `create_goal` / `update_goal` / `delete_goal` - Manage goals
- `calculate_goal` - Recalculate based on current stats

### Workouts
- `get_recent_workouts` / `list_workouts` / `get_workout` - View workouts
- `create_workout` / `update_workout` / `delete_workout` - Manage workouts

### Notes & Memory
- `get_notes` - View saved preferences
- `create_note` / `update_note` / `delete_note` - Manage notes

### Households
- `get_households` / `get_household_summary` - View households
- `create_household` / `update_household` / `delete_household` - Manage
- `list_household_members` / `remove_household_member` - Manage members
- `suggest_meal_to_member` - Create pending logs for family members

### Household Invites
- `list_household_invites` / `list_pending_invites` - View invites
- `create_household_invite` / `cancel_household_invite` - Send invites
- `accept_invite` / `decline_invite` / `accept_invite_by_token` - Respond

## Example Usage

Once configured and authenticated, you can ask Claude things like:

- "What have I eaten today?"
- "Log a lunch: grilled salmon (350 cal, 40g protein, 0g carbs, 20g fat)"
- "What are my remaining macros for today?"
- "Search for nutrition info on greek yogurt"
- "What meal suggestions do you have for dinner?"
- "Show me my recent workouts"
- "What's my current fitness goal?"
- "Remember that I'm lactose intolerant"
- "Plan dinner for my family tonight"

## Token Management

- Access tokens expire after 1 hour
- Refresh tokens are used automatically to get new access tokens
- Tokens are stored in `~/.databody_token.json` with 600 permissions
- Use the `logout` tool to clear stored tokens
- Use the `auth_status` tool to check if you're logged in

## Development

Run in development mode with hot reload:
```bash
npm run dev
```

Build for production:
```bash
npm run build
npm start
```

## Security Notes

- Uses OAuth 2.0 with PKCE for secure authentication
- No secrets stored in the MCP configuration
- Tokens are stored with restricted file permissions
- Automatic token refresh when expired
- Browser-based flow is recommended over password flow

## Troubleshooting

**"Not authenticated"**: Run the `authenticate` tool to login.

**"Session expired"**: Your token expired and couldn't be refreshed. Re-authenticate.

**OAuth callback fails**: Make sure port 8787 is available, or set `DATABODY_CALLBACK_PORT` to a different port.

**Connection refused**: Ensure the DataBody API is reachable at the configured URL.

## Links

- [DataBody App](https://databody.ai)
- [MCP Documentation](https://databody.ai/mcp)
- [API Documentation](https://databody.ai/api)
- [GitHub Issues](https://github.com/databody-ai/databody-mcp/issues)
