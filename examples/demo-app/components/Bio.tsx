// Demo app: deliberately insecure. Do not deploy.
export function Bio({profile}: {profile: {name: string; bioHtml: string}}) {
  return (
    <section>
      <h2>{profile.name}</h2>
      <div dangerouslySetInnerHTML={{__html: profile.bioHtml}} />
    </section>
  )
}
