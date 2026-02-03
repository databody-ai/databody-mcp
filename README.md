# DataBody MCP Server

An MCP (Model Context Protocol) server that allows Claude to interact with your DataBody health tracking data using secure OAuth authentication.

## Features

The MCP server provides tools for:

- **Authentication** - Secure OAuth2 login with PKCE support
- **Health Summary** - Get your daily macros, goals, body stats, and recent workouts
- **Nutrition Logging** - Log food items with full macro tracking
- **Food Search** - Search for foods and their nutrition information
- **Goal Management** - View and create fitness goals
- **AI Coach** - Chat with the AI nutrition coach
- **Meal Suggestions** - Get AI-powered meal suggestions based on remaining macros
- **Workout Tracking** - View recent workout logs

## Prerequisites

- Node.js 18+
- A running DataBody Rails server
- OAuth application credentials (see setup below)

## Installation

1. Navigate to the MCP directory:
   ```bash
   cd mcp
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the server:
   ```bash
   npm run build
   ```

## Configuration

Add the MCP server to your Claude Code config (`~/.claude.json`):

```json
{
  "mcpServers": {
    "databody": {
      "command": "node",
      "args": ["/path/to/databody/mcp/dist/index.js"],
      "env": {
        "DATABODY_API_URL": "http://localhost:3000"
      }
    }
  }
}
```

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
| `DATABODY_API_URL` | URL of your DataBody API | `http://localhost:3000` |
| `DATABODY_CALLBACK_PORT` | Port for OAuth callback server | `8787` |

## Available Tools

### Authentication Tools

#### `authenticate`
Authenticate with DataBody using OAuth.

**Parameters:**
- `method`: "browser" (recommended) or "password"
- `email`: Email address (required for password method)
- `password`: Password (required for password method)

#### `logout`
Log out and clear stored tokens.

#### `auth_status`
Check current authentication status.

### Data Tools

#### `get_health_summary`
Get your complete health dashboard including today's macros, active goals, latest weight/body fat, and recent workouts.

#### `get_today_nutrition`
Get all nutrition logs for today with detailed breakdowns by meal and item.

#### `log_food`
Log food items to your nutrition diary.

**Parameters:**
- `meal_type`: "breakfast", "lunch", "dinner", or "snack"
- `items`: Array of food items with name, calories, protein_grams, carbs_grams, fat_grams

**Example:**
```json
{
  "meal_type": "lunch",
  "items": [
    {
      "name": "Grilled Chicken Breast",
      "serving_size": "6 oz",
      "calories": 280,
      "protein_grams": 52,
      "carbs_grams": 0,
      "fat_grams": 6
    }
  ]
}
```

#### `search_food`
Search the food database for nutrition information.

**Parameters:**
- `query`: Search term (e.g., "chicken breast", "apple")

#### `get_current_goal`
Get your active fitness goal with daily calorie and macro targets.

#### `create_goal`
Create a new fitness goal.

**Parameters:**
- `daily_calorie_target`: Daily calorie goal
- `daily_protein_grams`: Daily protein target
- `daily_carbs_grams`: Daily carbs target
- `daily_fat_grams`: Daily fat target
- `strategy`: "cut", "maintain", or "bulk" (optional)
- `target_body_fat_percentage`: Target body fat % (optional)
- `target_date`: Target date in YYYY-MM-DD format (optional)

#### `get_recent_workouts`
Get your recent workout history.

**Parameters:**
- `limit`: Number of workouts to return (default: 10)

#### `ai_chat`
Chat with the AI nutrition coach for advice, questions, or guidance.

**Parameters:**
- `message`: Your message to the coach

#### `get_meal_suggestions`
Get AI-powered meal suggestions based on your remaining macros for the day.

**Parameters:**
- `preferences`: Optional dietary preferences (e.g., "vegetarian", "high protein")

#### `get_favorites`
Get your list of favorite foods for quick logging.

#### `get_recents`
Get your recently logged foods.

#### `delete_nutrition_item`
Delete a specific food item from a nutrition log.

**Parameters:**
- `log_id`: ID of the nutrition log
- `item_id`: ID of the item to delete

## Example Usage

Once configured and authenticated, you can ask Claude things like:

- "What have I eaten today?"
- "Log a lunch: grilled salmon (350 cal, 40g protein, 0g carbs, 20g fat)"
- "What are my remaining macros for today?"
- "Search for nutrition info on greek yogurt"
- "What meal suggestions do you have for dinner?"
- "Show me my recent workouts"
- "What's my current fitness goal?"

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

**Connection refused**: Ensure your DataBody Rails server is running at the configured URL.
