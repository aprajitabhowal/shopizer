function triggerCodeQL() {
  const repo = document.getElementById("repoUrl").value;
  const githubToken = document.getElementById("githubToken").value;
  document.getElementById("status").innerText = "Triggering CodeQL...";
  fetch("/trigger-codeql", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repo, github_token: githubToken })
  })
  .then(res => {
    if (!res.ok) throw new Error("Failed to trigger");
    return res.blob();
  })
  .then(blob => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "codeql-report.json";
    a.click();
    document.getElementById("status").innerText = "✅ CodeQL report downloaded.";
  })
  .catch(err => {
    document.getElementById("status").innerText = "❌ CodeQL failed: " + err.message;
  });
}

function triggerSonar() {
  const repo = document.getElementById("repoUrl").value;
  const sonarToken = document.getElementById("sonarToken").value;
  document.getElementById("status").innerText = "Triggering SonarQube...";
  fetch("/trigger-sonar", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repo, sonar_token: sonarToken })
  })
  .then(res => res.blob())
  .then(blob => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "sonarqube-report.json";
    a.click();
    document.getElementById("status").innerText = "✅ SonarQube report downloaded.";
  })
  .catch(err => {
    document.getElementById("status").innerText = "❌ SonarQube failed.";
    console.error(err);
  });
}

function triggerDependabot() {
  const repo = document.getElementById("repoUrl").value;
  const githubToken = document.getElementById("githubToken").value;
  document.getElementById("status").innerText = "Triggering Dependabot...";
  fetch("/trigger-dependabot", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repo, github_token: githubToken })
  })
  .then(res => res.blob())
  .then(blob => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "dependabot-report.json";
    a.click();
    document.getElementById("status").innerText = "✅ Dependabot report downloaded.";
  })
  .catch(err => {
    document.getElementById("status").innerText = "❌ Dependabot failed.";
    console.error(err);
  });
}