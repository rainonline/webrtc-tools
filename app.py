import flet as ft
from main import check_stun_server


def main(page: ft.Page):
    page.title = "WebRTC STUN Tester"
    page.theme_mode = ft.ThemeMode.SYSTEM
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.window.width = 480
    page.window.height = 800
    page.window.resizable = True

    def toggle_theme(e):
        page.theme_mode = ft.ThemeMode.LIGHT if page.theme_mode == ft.ThemeMode.DARK else ft.ThemeMode.DARK
        page.update()

    page.appbar = ft.AppBar(
        title=ft.Text("WebRTC STUN Tester"),
        center_title=True,
        actions=[
            ft.IconButton(ft.Icons.BRIGHTNESS_6, on_click=toggle_theme)
        ],
    )

    # State variables
    host_input = ft.TextField(label="STUN Host", value="stun.l.google.com", width=300)
    port_input = ft.TextField(label="Port", value="19302", width=100, keyboard_type=ft.KeyboardType.NUMBER)
    username_input = ft.TextField(label="Username (Optional)", width=410)
    password_input = ft.TextField(label="Password (Optional)",
                                  password=True, can_reveal_password=True, width=410)

    result_icon = ft.Icon(name=ft.Icons.HELP_OUTLINE, size=40, color=ft.Colors.GREY)
    result_text = ft.Text("Ready to test", size=20, weight=ft.FontWeight.BOLD)
    result_details = ft.Column(scroll=ft.ScrollMode.AUTO, height=150)

    loading_indicator = ft.ProgressRing(visible=False)
    test_button = ft.ElevatedButton(text="Test Connectivity", icon=ft.Icons.PLAY_ARROW, width=200)

    def log(message: str, color: str | None = None):
        result_details.controls.append(ft.Text(message, color=color, selectable=True))
        page.update()

    def on_test_click(e):
        # Reset UI
        result_details.controls.clear()
        result_icon.name = ft.Icons.HOURGLASS_EMPTY
        result_icon.color = ft.Colors.PRIMARY
        result_text.value = "Testing..."
        result_text.color = None
        loading_indicator.visible = True
        test_button.disabled = True
        page.update()

        try:
            host = host_input.value
            port = int(port_input.value)
            username = username_input.value if username_input.value else None
            password = password_input.value if password_input.value else None

            log(f"Connecting to {host}:{port}...", ft.Colors.PRIMARY)
            
            # Run the test
            # Note: In a real GUI app, network calls should be async or threaded to avoid freezing UI.
            # For this simple tool, we'll call it directly, but Flet handles it reasonably well for short tasks.
            result = check_stun_server(
                host=host,
                port=port,
                timeout=5.0,
                attempts=3,
                username=username,
                password=password
            )

            loading_indicator.visible = False
            test_button.disabled = False

            if result.success:
                result_icon.name = ft.Icons.CHECK_CIRCLE
                result_icon.color = ft.Colors.GREEN
                result_text.value = "Success!"
                result_text.color = ft.Colors.GREEN
                
                log(f"✅ Connected successfully!", ft.Colors.GREEN)
                if result.response_from:
                    log(f"Response from: {result.response_from[0]}:{result.response_from[1]}")
                log(f"Latency: {result.latency_ms:.2f} ms")
                log(f"Mapped Address: {result.mapped_address}:{result.mapped_port}", ft.Colors.SECONDARY)
            else:
                result_icon.name = ft.Icons.ERROR
                result_icon.color = ft.Colors.RED
                result_text.value = "Failed"
                result_text.color = ft.Colors.RED
                
                log(f"❌ Connection failed.", ft.Colors.RED)
                if result.error:
                    log(f"Error: {result.error}", ft.Colors.RED)

        except ValueError:
            loading_indicator.visible = False
            test_button.disabled = False
            result_icon.name = ft.Icons.WARNING
            result_icon.color = ft.Colors.ORANGE
            result_text.value = "Invalid Input"
            log("Please check port number.", ft.Colors.ORANGE)
        except Exception as ex:
            loading_indicator.visible = False
            test_button.disabled = False
            result_icon.name = ft.Icons.ERROR
            result_icon.color = ft.Colors.RED
            result_text.value = "Error"
            log(f"Unexpected error: {ex}", ft.Colors.RED)
        
        page.update()

    test_button.on_click = on_test_click

    # Layout
    page.add(
        ft.Card(
            content=ft.Container(
                padding=20,
                content=ft.Column(
                    [
                        # ft.Text("WebRTC STUN Tester", size=24, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
                        # ft.Divider(),
                        ft.Row([host_input, port_input], alignment=ft.MainAxisAlignment.CENTER),
                        username_input,
                        password_input,
                        ft.Divider(),
                        ft.Row([test_button, loading_indicator], alignment=ft.MainAxisAlignment.CENTER),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=20
                ),
            ),
            width=450,
        ),
        ft.Card(
            content=ft.Container(
                padding=20,
                content=ft.Column(
                    [
                        ft.Row([result_icon, result_text], alignment=ft.MainAxisAlignment.CENTER),
                        ft.Divider(),
                        ft.Container(
                            content=result_details,
                            bgcolor=ft.Colors.ON_INVERSE_SURFACE,
                            border_radius=5,
                            padding=10,
                            width=410
                        )
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER
                )
            ),
            width=450
        )
    )


if __name__ == "__main__":
    ft.app(target=main)
