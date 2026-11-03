import { useEffect, useState } from "react";
import { Icon } from "@/components/Icon";
import { generate, strength } from "@/lib/generate";
import type { Copy } from "./App";

interface Props {
  copy: Copy;
  back: () => void;
}

const suggestions = () => [generate("easy"), generate("random")];

export function Generator({ copy, back }: Props) {
  const [options, setOptions] = useState(suggestions);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        back();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [back]);

  return (
    <div className="screen">
      <div className="subbar">
        <button className="icon-button" title="Back" aria-label="Back" onClick={back} autoFocus>
          <Icon name="back" />
        </button>
        <h2>Generate password</h2>
      </div>
      <div className="form-body">
        <p className="muted">Copy a password to use or share. These passwords are not saved to Silo.</p>
        {options.map((option) => {
          const meter = strength(option.bits);
          const label = option.style === "easy" ? "Easy to type" : "Random";
          return (
            <div className="generated-password" key={option.style}>
              <h3>{label}</h3>
              <span className="generated-value mono">{option.password}</span>
              <span className={`meter l${meter.level}`}>
                <span className="bars" aria-hidden="true">
                  {[1, 2, 3, 4].map((n) => (
                    <i key={n} className={n <= meter.level ? "on" : ""} />
                  ))}
                </span>
                {meter.label} · {option.bits} bits
              </span>
              <button
                className="small"
                onClick={() => copy(option.password, "Password")}
                aria-label={`Copy ${label.toLowerCase()} password`}
              >
                <Icon name="copy" size={14} />
                Copy password
              </button>
            </div>
          );
        })}
      </div>
      <div className="footer">
        <button className="wide" onClick={() => setOptions(suggestions())}>
          <Icon name="refresh" size={14} />
          Other suggestions
        </button>
      </div>
    </div>
  );
}
