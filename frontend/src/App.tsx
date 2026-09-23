import { useEffect, useState } from "react";
import { Layout } from "./components/Layout";
import { useHashRoute } from "./hooks";
import { About } from "./pages/About";
import { Dashboard } from "./pages/Dashboard";
import { DetectionDetailPage, Detections } from "./pages/Detections";
import { EnvironmentDetailPage, Environments } from "./pages/Environments";
import { Events } from "./pages/Events";
import { RuleDetailPage, Rules } from "./pages/Rules";
import { Siem } from "./pages/Siem";
import { api } from "./services/api";
import type { About as AboutT } from "./types";

const HEX = /^#[0-9a-f]{3,8}$/i;

export default function App() {
  const [page = "dashboard", id] = useHashRoute();
  const [about, setAbout] = useState<AboutT | null>(null);

  useEffect(() => {
    api.about().then((a) => {
      setAbout(a);
      document.title = a.branding.project_name;
      if (HEX.test(a.branding.primary_brand_color)) document.documentElement.style.setProperty("--brand", a.branding.primary_brand_color);
    }).catch(() => {});
  }, []);

  let content;
  switch (page) {
    case "environments": content = id ? <EnvironmentDetailPage id={Number(id)} /> : <Environments />; break;
    case "rules": content = id ? <RuleDetailPage id={id} /> : <Rules />; break;
    case "events": content = <Events />; break;
    case "detections": content = id ? <DetectionDetailPage id={id} /> : <Detections />; break;
    case "siem": content = <Siem />; break;
    case "about": content = <About about={about} />; break;
    default: content = <Dashboard about={about} />;
  }
  return <Layout route={page} about={about}>{content}</Layout>;
}
