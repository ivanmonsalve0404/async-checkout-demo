import { Component, type ReactNode } from 'react';

interface Props {
  readonly children: ReactNode;
}

interface State {
  readonly failed: boolean;
}

export class AppErrorBoundary extends Component<Props, State> {
  public override state: State = { failed: false };

  public static getDerivedStateFromError(): State {
    return { failed: true };
  }

  public override componentDidCatch(): void {
    // Telemetry is intentionally omitted until the safe frontend port exists.
  }

  public override render(): ReactNode {
    if (this.state.failed) {
      return (
        <main id="main-content" className="app-shell">
          <section className="status-panel danger" role="alert">
            <h1>La aplicación no pudo continuar</h1>
            <p>Recarga la página. No se guardaron datos de pago.</p>
          </section>
        </main>
      );
    }
    return this.props.children;
  }
}
