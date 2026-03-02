import flet as ft
def main(page: ft.Page):
    def on_event(e):
        print(f"Event triggered via: {e.control.value}")
        
    d = ft.Dropdown(
        options=[ft.dropdown.Option("a"), ft.dropdown.Option("b")],
        # Testing what event triggers when dropdown val changes
        on_change=on_event, # If not allowed here, we use on_select
    )
    
    try:
        d2 = ft.Dropdown(options=[ft.dropdown.Option("a")], on_select=on_event)
        page.add(d2)
        print("on_select worked")
    except Exception as e:
        print("on_select failed", e)
        
    try:
        d3 = ft.Dropdown(options=[ft.dropdown.Option("a")], on_text_change=on_event)
        page.add(d3)
        print("on_text_change worked")
    except Exception as e:
        print("on_text_change failed", e)

ft.run(main)
