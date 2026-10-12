import "@fontsource-variable/manrope";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "./landing.css";

export default function LandingLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <div className="landing">{children}</div>;
}
