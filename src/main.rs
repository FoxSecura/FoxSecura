// SPDX-FileCopyrightText: 2026 FoxSecura contributors
// SPDX-License-Identifier: AGPL-3.0-only

mod app;

#[tokio::main]
async fn main() -> Result<(), app::Error> {
    app::App::from_env()?.run().await
}
