import flet as ft
from main import check_stun_server, detect_nat_type, NatType

class StunTester(ft.Container):
    def __init__(self):
        super().__init__(expand=True, padding=20)
        
        self.host_input = ft.TextField(label="STUN Host", value="stun.l.google.com", width=300)
        self.port_input = ft.TextField(label="Port", value="19302", width=100, keyboard_type=ft.KeyboardType.NUMBER)
        self.username_input = ft.TextField(label="Username (Optional)", width=410)
        self.password_input = ft.TextField(label="Password (Optional)", password=True, can_reveal_password=True, width=410)
        
        self.result_icon = ft.Icon(name=ft.Icons.HELP_OUTLINE, size=40, color=ft.Colors.GREY)
        self.result_text = ft.Text("Ready to test", size=20, weight=ft.FontWeight.BOLD)
        self.result_details = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=6)
        
        self.loading_indicator = ft.ProgressRing(visible=False)
        self.test_button = ft.ElevatedButton(text="Test Connectivity", icon=ft.Icons.PLAY_ARROW, width=200, on_click=self.run_test)

        input_form = ft.Card(
            content=ft.Container(
                padding=20,
                content=ft.Column(
                    [
                        ft.Text("STUN Connectivity Tester", size=22, weight=ft.FontWeight.BOLD),
                        ft.ResponsiveRow(
                            [
                                ft.Container(self.host_input, col={'xs': 12, 'sm': 8}),
                                ft.Container(self.port_input, col={'xs': 12, 'sm': 4}),
                            ],
                            run_spacing=12,
                        ),
                        self.username_input,
                        self.password_input,
                        ft.Row([self.test_button, self.loading_indicator], alignment=ft.MainAxisAlignment.START, spacing=12),
                    ],
                    spacing=16,
                ),
            )
        )

        result_panel = ft.Card(
            content=ft.Container(
                padding=20,
                content=ft.Column(
                    [
                        ft.Row([self.result_icon, self.result_text], alignment=ft.MainAxisAlignment.START, spacing=12),
                        ft.Container(
                            content=self.result_details,
                            padding=10,
                            bgcolor=ft.Colors.SECONDARY_CONTAINER,
                            border_radius=ft.border_radius.all(12),
                            expand=True,
                        ),
                    ],
                    spacing=16,
                ),
            ),
        )

        self.content = ft.Column(
            [input_form, result_panel],
            spacing=24,
            expand=True,
        )

    def log(self, message: str, color: str | None = None):
        self.result_details.controls.append(ft.Text(message, color=color, selectable=True))
        self.result_details.update()

    def run_test(self, e):
        self.result_details.controls.clear()
        self.result_icon.name = ft.Icons.HOURGLASS_EMPTY
        self.result_icon.color = ft.Colors.PRIMARY
        self.result_text.value = "Testing..."
        self.result_text.color = None
        self.loading_indicator.visible = True
        self.test_button.disabled = True
        self.update()

        try:
            host = self.host_input.value or ""
            port = int(self.port_input.value or "0")
            username = self.username_input.value if self.username_input.value else None
            password = self.password_input.value if self.password_input.value else None

            self.log(f"Connecting to {host}:{port}...", ft.Colors.PRIMARY)
            
            result = check_stun_server(host, port, 5.0, 3, username, password)

            if result.success:
                self.result_icon.name = ft.Icons.CHECK_CIRCLE
                self.result_icon.color = ft.Colors.GREEN
                self.result_text.value = "Success!"
                self.result_text.color = ft.Colors.GREEN
                self.log(f"✅ Connected successfully!", ft.Colors.GREEN)
                if result.response_from:
                    self.log(f"Response from: {result.response_from[0]}:{result.response_from[1]}")
                self.log(f"Latency: {result.latency_ms:.2f} ms")
                self.log(f"Mapped Address: {result.mapped_address}:{result.mapped_port}", ft.Colors.SECONDARY)
            else:
                self.result_icon.name = ft.Icons.ERROR
                self.result_icon.color = ft.Colors.RED
                self.result_text.value = "Failed"
                self.result_text.color = ft.Colors.RED
                self.log(f"❌ Connection failed.", ft.Colors.RED)
                if result.error:
                    self.log(f"Error: {result.error}", ft.Colors.RED)

        except Exception as ex:
            self.result_icon.name = ft.Icons.ERROR
            self.result_icon.color = ft.Colors.RED
            self.result_text.value = "Error"
            self.log(f"Error: {ex}", ft.Colors.RED)
        
        self.loading_indicator.visible = False
        self.test_button.disabled = False
        self.update()

class NatDetector(ft.Container):
    def __init__(self):
        super().__init__(expand=True, padding=20)
        
        self.nat_result_icon = ft.Icon(name=ft.Icons.HELP_OUTLINE, size=40, color=ft.Colors.GREY)
        self.nat_result_text = ft.Text("Ready to detect", size=20, weight=ft.FontWeight.BOLD)
        self.nat_result_details = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=6)
        self.nat_loading_indicator = ft.ProgressRing(visible=False)
        self.nat_detect_button = ft.ElevatedButton(text="Detect NAT Type", icon=ft.Icons.ROUTER, width=200, on_click=self.run_detect)

        primary_actions = ft.Card(
            content=ft.Container(
                padding=20,
                content=ft.Column(
                    [
                        ft.Text("NAT Type Detection", size=22, weight=ft.FontWeight.BOLD),
                        ft.Row([self.nat_detect_button, self.nat_loading_indicator], spacing=12),
                    ],
                    spacing=16,
                ),
            )
        )

        nat_results = ft.Card(
            content=ft.Container(
                padding=20,
                content=ft.Column(
                    [
                        ft.Row([self.nat_result_icon, self.nat_result_text], spacing=12),
                        ft.Container(
                            content=self.nat_result_details,
                            padding=10,
                            bgcolor=ft.Colors.SECONDARY_CONTAINER,
                            border_radius=ft.border_radius.all(12),
                            expand=True,
                        ),
                    ],
                    spacing=16,
                ),
            )
        )

        self.content = ft.Column(
            [primary_actions, nat_results],
            spacing=24,
            expand=True,
        )

    def log(self, message: str, color: str | None = None):
        self.nat_result_details.controls.append(ft.Text(message, color=color, selectable=True))
        self.nat_result_details.update()

    def run_detect(self, e):
        self.nat_result_details.controls.clear()
        self.nat_result_icon.name = ft.Icons.HOURGLASS_EMPTY
        self.nat_result_icon.color = ft.Colors.PRIMARY
        self.nat_result_text.value = "Detecting..."
        self.nat_result_text.color = None
        self.nat_loading_indicator.visible = True
        self.nat_detect_button.disabled = True
        self.update()

        try:
            self.log("🔍 Querying STUN servers...", ft.Colors.PRIMARY)
            
            result = detect_nat_type(timeout=5.0)

            nat_type_config = {
                NatType.OPEN: (ft.Icons.PUBLIC, ft.Colors.GREEN, "🌐"),
                NatType.FULL_CONE: (ft.Icons.CHECK_CIRCLE, ft.Colors.GREEN, "🟢"),
                NatType.RESTRICTED_CONE: (ft.Icons.WARNING, ft.Colors.YELLOW, "🟡"),
                NatType.PORT_RESTRICTED_CONE: (ft.Icons.WARNING, ft.Colors.ORANGE, "🟠"),
                NatType.SYMMETRIC: (ft.Icons.ERROR, ft.Colors.RED, "🔴"),
                NatType.BLOCKED: (ft.Icons.BLOCK, ft.Colors.RED, "⛔"),
                NatType.UNKNOWN: (ft.Icons.HELP_OUTLINE, ft.Colors.GREY, "❓"),
            }

            icon, color, emoji = nat_type_config.get(
                result.nat_type, 
                (ft.Icons.HELP_OUTLINE, ft.Colors.GREY, "❓")
            )

            self.nat_result_icon.name = icon
            self.nat_result_icon.color = color
            self.nat_result_text.value = result.nat_type.value
            self.nat_result_text.color = color

            self.log(f"{emoji} NAT Type: {result.nat_type.value}", color)
            if result.external_ip:
                self.log(f"External Address: {result.external_ip}:{result.external_port}")
            if result.details:
                self.log(f"Details: {result.details}", ft.Colors.SECONDARY)

        except Exception as ex:
            self.nat_result_icon.name = ft.Icons.ERROR
            self.nat_result_icon.color = ft.Colors.RED
            self.nat_result_text.value = "Error"
            self.log(f"Error: {ex}", ft.Colors.RED)
        
        self.nat_loading_indicator.visible = False
        self.nat_detect_button.disabled = False
        self.update()

def main(page: ft.Page):
    page.title = "WebRTC Tools"
    page.theme_mode = ft.ThemeMode.SYSTEM
    page.theme = ft.Theme(color_scheme_seed=ft.Colors.BLUE, use_material3=True)
    page.dark_theme = ft.Theme(color_scheme_seed=ft.Colors.BLUE, use_material3=True)
    page.padding = 0
    
    # Views
    stun_tester = StunTester()
    nat_detector = NatDetector()
    views = [stun_tester, nat_detector]
    
    # Navigation State
    current_view_index = 0
    
    def change_view(index):
        nonlocal current_view_index
        if index == current_view_index:
            return
        current_view_index = index
        # Update Rail
        rail.selected_index = index
        # Update Drawer
        drawer.selected_index = index
        # Update Content
        content_area.content = views[index]
        page.update()

    def on_nav_change(e):
        selected = getattr(e.control, "selected_index", 0) or 0
        change_view(selected)
        if isinstance(e.control, ft.NavigationDrawer) and page.drawer is not None:
            page.drawer.open = False
            page.update()

    # Navigation Controls
    nav_items = [
        ft.NavigationRailDestination(
            icon=ft.Icons.NETWORK_CHECK, 
            selected_icon=ft.Icons.NETWORK_CHECK, 
            label="Connectivity"
        ),
        ft.NavigationRailDestination(
            icon=ft.Icons.ROUTER, 
            selected_icon=ft.Icons.ROUTER, 
            label="NAT Type"
        ),
    ]
    
    drawer_items = [
        ft.NavigationDrawerDestination(
            icon=ft.Icons.NETWORK_CHECK, 
            label="Connectivity"
        ),
        ft.NavigationDrawerDestination(
            icon=ft.Icons.ROUTER, 
            label="NAT Type"
        ),
    ]

    rail = ft.NavigationRail(
        selected_index=0,
        label_type=ft.NavigationRailLabelType.ALL,
        min_width=100,
        min_extended_width=400,
        destinations=nav_items,
        on_change=on_nav_change
    )

    drawer = ft.NavigationDrawer(
        controls=[
            ft.Container(height=12),
            ft.Text("WebRTC Tools", size=24, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
            ft.Divider(),
            *drawer_items,
        ],
        on_change=on_nav_change,
        selected_index=0
    )

    # Layout Elements
    content_area = ft.Container(expand=True, content=stun_tester)
    divider = ft.VerticalDivider(width=1)
    
    # Theme Toggle
    def toggle_theme(e):
        page.theme_mode = ft.ThemeMode.LIGHT if page.theme_mode == ft.ThemeMode.DARK else ft.ThemeMode.DARK
        page.update()

    # AppBar (for mobile)
    def open_drawer(e):
        if page.drawer is not None:
            page.drawer.open = True
            page.update()

    appbar = ft.AppBar(
        leading=ft.IconButton(ft.Icons.MENU, on_click=open_drawer),
        title=ft.Text("WebRTC Tools"),
        center_title=True,
        actions=[
            ft.IconButton(ft.Icons.BRIGHTNESS_6, on_click=toggle_theme)
        ],
    )
    
    # Responsive Logic
    def handle_resize(e):
        width = (page.width or 0)
        if width == 0 and page.window is not None:
            width = page.window.width or 0
        if width >= 700:
            # Desktop/Tablet Mode
            rail.visible = True
            divider.visible = True
            page.appbar = None # Remove appbar
        else:
            # Mobile Mode
            rail.visible = False
            divider.visible = False
            page.appbar = appbar # Add appbar
        page.update()

    page.on_resized = handle_resize
    page.drawer = drawer
    
    # Initial Layout Construction
    page.add(
        ft.Row(
            [
                rail,
                divider,
                content_area,
            ],
            expand=True,
        )
    )
    
    # Trigger initial resize check
    handle_resize(None)

if __name__ == "__main__":
    ft.app(target=main)
