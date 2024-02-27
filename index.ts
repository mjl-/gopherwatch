const errmsg = (err: unknown) => ''+((err as any).message || '(no error message)')

const zindexes = {
	popup: '1',
	login: '2',
}

const check = async <T>(elem: { disabled: boolean }, fn: () => Promise<T>): Promise<T> => {
	elem.disabled = true
	try {
		return await fn()
	} catch (err) {
		console.log('error', err)
		window.alert('Error: ' + errmsg(err))
		throw err
	} finally {
		elem.disabled = false
	}
}

let popupOpen = false
const popup = (...kids: ElemArg[]) => {
	const origFocus = document.activeElement
	const close = () => {
		if (!root.parentNode) {
			return
		}
		popupOpen = false
		root.remove()
		if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
			origFocus.focus()
		}
	}
	let content: HTMLElement
	const root = dom.div(
		style({position: 'fixed', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: 'rgba(0, 0, 0, 0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: zindexes.popup}),
		function keydown(e: KeyboardEvent) {
			if (e.key === 'Escape') {
				e.stopPropagation()
				close()
			}
		},
		function click(e: MouseEvent) {
			e.stopPropagation()
			close()
		},
		content=dom.div(
			attr.tabindex('0'),
			style({backgroundColor: 'white', borderRadius: '.25em', padding: '1em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd', maxWidth: '95vw', overflowX: 'auto', maxHeight: '95vh', overflowY: 'auto'}),
			function click(e: MouseEvent) {
				e.stopPropagation()
			},
			kids,
		)
	)
	popupOpen = true
	document.body.appendChild(root)
	content.focus()
	return close
}

let loginOpen = false
const login = async (reason: string) => {
	console.log('login needed', reason)
	return new Promise<string>((resolve: (v: string) => void, _) => {
		const origFocus = document.activeElement
		let reasonElem: HTMLElement
		let fieldset: HTMLFieldSetElement
		let autosize: HTMLElement
		let username: HTMLInputElement
		let password: HTMLInputElement
		const root = dom.div(
			style({position: 'fixed', top: 0, right: 0, bottom: 0, left: 0, backgroundColor: '#eee', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: zindexes.login, animation: 'fadein .15s ease-in'}),
			dom.div(
				reasonElem=reason ? dom.div(style({marginBottom: '2ex', textAlign: 'center'}), reason) : dom.div(),
				dom.div(
					style({backgroundColor: 'white', borderRadius: '.25em', padding: '1em', boxShadow: '0 0 20px rgba(0, 0, 0, 0.1)', border: '1px solid #ddd', maxWidth: '95vw', overflowX: 'auto', maxHeight: '95vh', overflowY: 'auto', marginBottom: '20vh'}),
					dom.form(
						async function submit(e: SubmitEvent) {
							e.preventDefault()
							e.stopPropagation()

							reasonElem.remove()

							await check(fieldset, async () => {
								const prepToken = await client.Prep()
								const csrftoken = await client.Login(prepToken, username.value, password.value)
								localStorageSet("gopherwatchcsrftoken", csrftoken)

								root.remove()
								loginOpen = false
								if (origFocus && origFocus instanceof HTMLElement && origFocus.parentNode) {
									origFocus.focus()
								}
								resolve(csrftoken)
							})
						},
						fieldset=dom.fieldset(
							dom.h1('Login'),
							dom.label(
								style({display: 'block', marginBottom: '2ex'}),
								dom.div('Email address', style({marginBottom: '.5ex'})),
								autosize=dom.span(dom._class('autosize'),
									username=dom.input(
										attr.required(''),
										function change() { autosize.dataset.value = username.value },
										function input() { autosize.dataset.value = username.value },
									),
								),
							),
							dom.label(
								style({display: 'block', marginBottom: '2ex'}),
								dom.div('Password', style({marginBottom: '.5ex'})),
								password=dom.input(attr.type('password'), attr.required('')),
							),
							dom.div(
								style({textAlign: 'center'}),
								dom.submitbutton('Login'),
							),
							dom.br(),
							dom.div(
								style({fontSize: '.85em'}),
								dom.a(attr.href('#'), 'Forgot password?', function click(e: MouseEvent) {
									e.preventDefault()
									requestPasswordReset()
								}),
							),
						),
					)
				)
			)
		)
		document.body.appendChild(root)
		username.focus()
		loginOpen = true
	})
}

const passwordResetRequested = () => {
	dom._kids(document.body,
		dom.div(dom._class('page'),
			dom.h1('Password reset requested!'),
			dom.p("We've sent you an email with a link for a password reset."),
			dom.p("Unless we've received too many request to send email to your address recently. Or if there is no account for your email address."),
			dom.p(dom.a(attr.href('#'), 'To home', function click() {
				// Reload to get rid of the login window that may still be capturing auth api errors.
				window.location.hash = '#'
				window.location.reload()
			})),
		)
	)
}

const requestPasswordReset = () => {
	let fieldset: HTMLFieldSetElement
	let email: HTMLInputElement

	dom._kids(document.body,
		dom.div(dom._class('page'),
			dom.h1('Request password reset'),
			dom.p("We'll send you an email with a link with which you can set a new password."),
			dom.form(
				async function submit(e: SubmitEvent) {
					e.preventDefault()
					e.stopPropagation()

					await check(fieldset, async () => {
						const prepToken = await client.Prep()
						await client.RequestPasswordReset(prepToken, email.value)
						passwordResetRequested()
					})
				},
				fieldset=dom.fieldset(
					dom.label(
						'Email address',
						dom.div(email=dom.input(attr.type('email'), attr.required(''))),
					),
					dom.br(),
					dom.div(dom.submitbutton('Request password reset')),
				)
			)
		)
	)
	email.focus()
}

// localstorage that ignores errors (e.g. in private mode).
const localStorageGet = (k: string) => {
	try {
		return JSON.parse(window.localStorage.getItem(k) || '')
	} catch (err) {
		return ''
	}
}
const localStorageSet = (k: string, v: any) => {
	try {
		window.localStorage.setItem(k, JSON.stringify(v))
	} catch (err) {}
}

let client: api.Client
const reinitClient = () => {
	client = new api.Client().withOptions({csrfHeader: 'x-csrf', login: login}).withAuthToken(localStorageGet('gopherwatchcsrftoken') || '')
}
reinitClient()

const subscriptionPopup = (sub: api.Subscription, subscriptions: api.Subscription[], render: () => void) => {
	let fieldset: HTMLFieldSetElement
	let module: HTMLInputElement
	let gomod: HTMLTextAreaElement
	let modulegomod: HTMLElement
	let indirect: HTMLInputElement
	let belowModule: HTMLInputElement
	let olderVersions: HTMLInputElement
	let pseudo: HTMLInputElement
	let prerelease: HTMLInputElement
	let comment: HTMLTextAreaElement
	let submitbtn: HTMLButtonElement

	const close = popup(
		dom.h1(sub.ID ? 'Edit subscription' : 'New subscription'),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.stopPropagation()
				e.preventDefault()

				let nsub: api.Subscription = {
					ID: sub.ID,
					Module: module.value,
					BelowModule: belowModule.checked,
					OlderVersions: olderVersions.checked,
					Pseudo: pseudo.checked,
					Prerelease: prerelease.checked,
					Comment: comment.value,
				}

				await check(fieldset, async () => {
					if (sub.ID) {
						await client.SubscriptionSave(nsub)
						subscriptions.splice(subscriptions.indexOf(sub), 1, nsub)
					} else if (gomod) {
						let imp: api.SubscriptionImport = {
							GoMod: gomod.value,
							BelowModule: belowModule.checked,
							OlderVersions: olderVersions.checked,
							Pseudo: pseudo.checked,
							Prerelease: prerelease.checked,
							Comment: comment.value,
							Indirect: indirect.checked,
						}
						const subs = await client.SubscriptionImport(imp)
						subscriptions.push(...(subs || []))
					} else {
						const xsub = await client.SubscriptionCreate(nsub)
						subscriptions.push(xsub)
					}
					render()
					close()
				})
			},
			fieldset=dom.fieldset(
				modulegomod=dom.div(
					dom.label(
						style({display: 'flex', justifyContent: 'space-between'}),
						dom.div('Module '),
						sub.ID ? [] : [
							dom.a(attr.href('#'), style({fontSize: '.9em'}), 'Subscribe to dependencies of a go.mod file', function click(e: MouseEvent) {
								e.preventDefault()
								dom._kids(modulegomod,
									dom.label(
										'Contents of go.mod',
										gomod=dom.textarea(attr.required(''), attr.rows('12')),
									),
									dom.div(dom._class('explain'), 'Paste the contents of your go.mod. Subscriptions will be created for all direct dependencies.'),
									dom.label(indirect=dom.input(attr.type('checkbox')), ' Also subscribe to indirect dependencies'),
									dom.br(),
								)
								dom._kids(submitbtn, 'Add subscriptions for dependencies')
							}),
						],
					),
					dom.div(
						module=dom.input(attr.required(''), attr.value(sub.Module)),
						dom.div(dom._class('explain'), 'Enter a single module as you would use in a Go import statement.', dom.br(), 'Example: github.com/mjl-/gopherwatch, github.com/mjl- or golang.org.'),
					),
				),
				dom.br(),
				dom.b('Notify about ...'),
				dom.label(belowModule=dom.input(attr.type('checkbox'), sub.BelowModule ? attr.checked('') : []), ' ', dom.span('Sub modules', attr.title('E.g. if subscribed to github.com/mjl-, whether to match github.com/mjl-/gopherwatch.'))),
				dom.label(olderVersions=dom.input(attr.type('checkbox'), sub.OlderVersions ? attr.checked('') : []), ' ', dom.span('Older versions than already seen', attr.title('Can happen when an old version (tag) is requested through the Go module proxy after a later tag, not uncommon after forking a repository and pushing all historic tags.'))),
				dom.label(prerelease=dom.input(attr.type('checkbox'), sub.Prerelease ? attr.checked('') : []), ' Prereleases such as v1.2.3-beta1'),
				dom.label(pseudo=dom.input(attr.type('checkbox'), sub.Pseudo ? attr.checked('') : []), ' Pseudo versions, such as v0.0.0-20240222094833-a1bd684a916b'),
				dom.br(),
				dom.label(
					'Comment',
					// explicit String to prevent special scriptswitch handling
					comment=dom.textarea(new String(sub.Comment)),
				),
				dom.br(),
				dom.div(submitbtn=dom.submitbutton(sub.ID ? 'Save subscription' : 'Add subscription')),
			),
		)
	)
	module.focus()
}

const overview = async () => {
	const overview = await client.Overview()
	let subscriptions: api.Subscription[] = overview.Subscriptions || []
	let moduleUpdates: api.ModuleUpdateURLs[] = overview.ModuleUpdates || []
	
	let substbody: HTMLElement
	let moduptbody: HTMLElement

	const render = () => {
		const nsubs = dom.tbody(
			subscriptions.length === 0 ? dom.tr(dom.td(attr.colspan('7'), 'No subscriptions yet, add the first one!')) : [],
			subscriptions.map(sub => {
				const row = dom.tr(
					dom.td(sub.Module),
					dom.td(sub.BelowModule ? 'Yes' : 'No'),
					dom.td(sub.OlderVersions ? 'Yes' : 'No'),
					dom.td(sub.Prerelease ? 'Yes' : 'No'),
					dom.td(sub.Pseudo ? 'Yes' : 'No'),
					dom.td(style({maxWidth: '40em'}), sub.Comment),
					dom.td(
						dom.clickbutton('Edit', function click() { subscriptionPopup(sub, subscriptions, render) }), ' ',
						dom.clickbutton('Remove', async function click(e: MouseEvent) {
							if (!window.confirm('Are you sure?')) {
								return
							}
							await check(e.target! as HTMLButtonElement, async () => {
								await client.SubscriptionRemove(sub.ID)
								subscriptions.splice(subscriptions.indexOf(sub), 1)
								render()
							})
						}),
					),
				)
				return row
			}),
		)
		substbody.replaceWith(nsubs)
		substbody = nsubs

		const nmodups = dom.tbody(
			moduleUpdates.length === 0 ? dom.tr(dom.td(attr.colspan('5'), 'No module updates.')) : [],
			moduleUpdates.map(modup => {
				const link = (anchor: string, url: string) => dom.a(attr.href(url), anchor, attr.rel('noopener'))
				const row = dom.tr(
					dom.td(link(modup.Module, modup.RepoURL || 'https://'+modup.Module)),
					dom.td(modup.TagURL ? link(modup.Version, modup.TagURL) : modup.Version),
					dom.td(modup.MessageID ? 'Yes' : 'No'),
					dom.td(modup.Discovered ? age(modup.Discovered) : []),
					dom.td(modup.DocURL ? link('Doc', modup.DocURL) : []),
				)
				return row
			}),
		)
		moduptbody.replaceWith(nmodups)
		moduptbody = nmodups
	}

	let intervalFieldset: HTMLFieldSetElement
	let interval: HTMLSelectElement

	const page = dom.div(
		dom._class('page'), dom._class('overview'),
		dom.div(
			style({display: 'flex', justifyContent: 'space-between'}),
			dom.div(
				dom.p(dom.a(attr.href('#'), '← Home')),
			),
			dom.div(
				overview.Email, ' ',
				dom.clickbutton('Logout', async function click() {
					try {
						await client.Logout()
					} catch (err) {
						window.alert('Error: ' + errmsg(err))
					} finally {
						localStorageSet('gopherwatchcsrftoken', '')
						reinitClient()
						window.location.hash = ''
					}
				}),
			),
		),
		dom.h1('Overview'),
		dom.div(
			dom.h2(style({display: 'inline-block'}), 'Subscriptions'), ' ',
			dom.clickbutton('Add', function click() {
				const nsub: api.Subscription = {
					ID: 0,
					Module: '',
					BelowModule: true,
					OlderVersions: false,
					Prerelease: false,
					Pseudo: false,
					Comment: '',
				}
				subscriptionPopup(nsub, subscriptions, render)
			}),
		),
		dom.br(),
		dom.table(
			dom.tr(
				dom.th('Module'),
				dom.th('Below module'),
				dom.th('Older versions'),
				dom.th('Prereleases'),
				dom.th('Pseudo versions'),
				dom.th('Comment'),
				dom.th('Action'),
			),
			substbody=dom.tbody(),
		),
		dom.br(),

		dom.h2('Notifications'),
		(() => {
			const render = () => {
				let elem = dom.div(
					dom.p('Change the kind of email messages you will receive:'),
					dom.table(
						dom.tr(dom.th('Kind'), dom.th('Status'), dom.th('Action')),
						dom.tr(
							dom.td('Service messages', attr.title('Like password reset and announcements.')),
							dom.td(overview.MetaUnsubscribed ? 'Unsubscribed' : 'Subscribed'),
							dom.clickbutton(overview.MetaUnsubscribed ? 'Resubscribe' : 'Unsubscribe', async function click(e: MouseEvent) {
								await check(e.target! as HTMLButtonElement, async () => {
									await client.SubscribeSet(true, !overview.MetaUnsubscribed)
									overview.MetaUnsubscribed = !overview.MetaUnsubscribed
									elem.replaceWith(render())
								})
							}),
						),
						dom.tr(
							dom.td('Module updates'),
							dom.td(overview.UpdatesUnsubscribed ? 'Unsubscribed' : 'Subscribed'),
							dom.clickbutton(overview.UpdatesUnsubscribed ? 'Resubscribe' : 'Unsubscribe', async function click(e: MouseEvent) {
								await check(e.target! as HTMLButtonElement, async () => {
									await client.SubscribeSet(false, !overview.UpdatesUnsubscribed)
									overview.UpdatesUnsubscribed = !overview.UpdatesUnsubscribed
									elem.replaceWith(render())
								})
							}),
						),
					),
					dom.br(),
				)
				return elem
			}
			return render()
		})(),

		dom.h2('Health'),
		dom.p("If we received notifications about failures to deliver email to you, we'll back off sending more messages. After a while we try again. If the problem persists, we stop sending notifications altogether."),
		dom.div('Current back off period: ', overview.Backoff.substring(0, 1).toUpperCase() + overview.Backoff.substring(1)),
		overview.Backoff !== 'none' && overview.Backoff !== 'permanent' ? dom.div(overview.BackoffUntil.toISOString()) : [],
		dom.br(),

		dom.h2('Interval'),
		dom.div(
			dom.form(
				async function submit(e: SubmitEvent) {
					e.preventDefault()
					e.stopPropagation()
					await check(intervalFieldset, async () => {
						await client.IntervalSet(interval.value as api.Interval)
					})
				},
				intervalFieldset=dom.fieldset(
					dom.label(
						style({display: 'inline'}),
						dom.div('Minimum time between two notification emails'),
						interval=dom.select(
							dom.option('Immediate', attr.value('immediate'), overview.UpdateInterval === api.Interval.IntervalImmediate ? attr.selected('') : []),
							dom.option('1 hour', attr.value('hour'), overview.UpdateInterval === api.Interval.IntervalHour ? attr.selected('') : []),
							dom.option('1 day', attr.value('day'), overview.UpdateInterval === api.Interval.IntervalDay ? attr.selected('') : []),
							dom.option('1 week', attr.value('week'), overview.UpdateInterval === api.Interval.IntervalWeek ? attr.selected('') : []),
						),
					),' ',
					dom.submitbutton('Save'),
					dom.div(dom._class('explain'), 'Selected interval may be extended by a server-configured minimum interval.'),
				),
			),
		),
		dom.br(),

		dom.h2('Recent module updates'),
		dom.table(
			dom.tr(
				dom.th('Module', attr.title('Repo URLs are guesses and may be wrong.')),
				dom.th('Version', attr.title('Tag URLs are guesses and may be wrong.')),
				dom.th('Notified'),
				dom.th('Age'),
				dom.th('Docs', attr.title('Doc URLs are guesses and may be wrong.')),
			),
			moduptbody=dom.tbody(),
		),
		dom.br(),

		dom.h2('History'),
		dom.p('Changes to your account over time, from new to old.'),
		dom.table(
			dom.tr(
				dom.th('Age'), dom.th('Description'),
			),
			(overview.UserLogs || []).map(l => dom.tr(
				dom.td(age(l.Time)),
				dom.td(l.Text),
			)),
		),
		dom.br(),

		dom.h2('Danger'),
		dom.clickbutton('Remove account', async function click(e: MouseEvent) {
			if (!window.confirm('Your account and all associated data will be permanently deleted. Are you sure?')) {
				return
			}
			await check(e.target! as HTMLButtonElement, async () => {
				await client.UserRemove()
				window.alert('Account has been removed')
				localStorageSet('gopherwatchcsrftoken', '')
				reinitClient()
				window.location.hash = '#'
			})
		})
	)
	render()
	dom._kids(document.body, page)
}

const signedup = (email: string) => {
	dom._kids(document.body,
		dom.div(dom._class('page'),
			dom.h1('Account created'),
			dom.p("We've sent an email to ", dom.b(email), " with a confirmation link."),
			dom.p("If the email is not coming in, don't forget to check your spam mailbox. Also, some mail servers employ 'grey listing', holding off first-time deliveries for up to half an hour."),
			dom.p("Go back ", dom.a(attr.href('#'), 'home', function click() { route() }), '.'),
		),
	)
}

const signup = (note: string) => {
	let fieldset: HTMLFieldSetElement
	let email: HTMLInputElement

	dom._kids(document.body,
		dom.div(dom._class('page'),
			dom.p('← ', dom.a(attr.href('#'), 'Home', function click() { route() })),
			dom.h1('Create account'),
			note ? [
				dom.pre(dom._class('mono'), style({whiteSpace: 'pre-wrap', padding: '1em', backgroundColor: '#eee', borderRadius: '.25em'}), note),
				dom.br(),
			] : [],
			dom.p("We'll send you an email with a confirmation link."),
			dom.form(
				async function submit(e: SubmitEvent) {
					e.stopPropagation()
					e.preventDefault()

					await check(fieldset, async () => {
						await client.Signup(email.value.trim())
						signedup(email.value.trim())
					})
				},
				fieldset=dom.fieldset(
					dom.label(
						'Email address',
						dom.div(email=dom.input(attr.type('email'), attr.required(''))),
					),
					dom.br(),
					dom.div(dom.submitbutton('Create account')),
				),
			)
		)
	)
	email.focus()
}

const age = (date: Date) => {
	const nowSecs = new Date().getTime()/1000
	let t = nowSecs - date.getTime()/1000
	let negative = ''
	if (t < 0) {
		negative = '-'
		t = -t
	}
	const minute = 60
	const hour = 60*minute
	const day = 24*hour
	const periods = [day, hour, minute]
	const suffix = ['d', 'h', 'min']
	let s
	for (let i = 0; i < periods.length; i++) {
		const p = periods[i]
		if (t >= 2*p || i === periods.length-1) {
			const n = Math.round(t/p)
			s = '' + n + suffix[i]
			break
		}
	}
	if (t < 60) {
		s = '<1min'
		// Prevent showing '-<1min' when browser and server have relatively small time drift of max 1 minute.
		negative = ''
	}
	s = negative+s
	return dom.span(s, attr.title(date.toISOString()))
}

const home = async () => {
	let home = await client.Home()

	const link = (anchor: string, url: string) => dom.a(attr.href(url), anchor, attr.rel('noopener'))
	let recentsElem = dom.tbody()
	const renderRecents = (l: api.Recent[], more: boolean) => {
		dom._kids(recentsElem,
			l.length === 0 ? dom.tr(dom.td(attr.colspan('4'), 'No recent packages.')) : [],
			l.map(r => {
				return dom.tr(
					dom.td(link(r.Module, r.RepoURL || 'https://'+r.Module)),
					dom.td(r.TagURL ? link(r.Version, r.TagURL) : r.Version),
					dom.td(age(r.Discovered)),
					dom.td(r.DocURL ? link('Doc', r.DocURL) : []),
				)
			}),
			more ? dom.tr(dom.td(dom.clickbutton('More...', dom._class('regular')), async function click(e: MouseEvent) {
				await check(e.target! as HTMLButtonElement, async () => {
					const xl = await client.Recents()
					renderRecents(xl || [], false)
				})
			})) : [],
		)
	}
	renderRecents(home.Recents || [], true)

	dom._kids(document.body,
		dom.div(dom._class('home'), dom._class('page'),
			dom.div(
				style({textAlign: 'right'}),
				dom.a(attr.href('#overview'), 'Login'),
			),
			dom.h1('GopherWatch'),
			dom.p('Keep tabs on Go modules.'),
			dom.p('Subscribe to Go module paths and receive an email when a new module/version is published through the Go module proxy.'),
			dom.h2('How does it work?'),
			dom.p('In Go, you use ', dom.span('"go get"', attr.title('Or related commands, such as "go install", "go mod tidy" and more')), ' to download Go modules to use as a dependency. Looking up a module is done through the ', dom.a(attr.href('https://sum.golang.org'), attr.rel('noopener'), 'Go checksum database'), ': A ', dom.a(attr.href('https://research.swtch.com/tlog'), attr.rel('noopener'), 'transparency log'), ' that proves it is not tampered with, providing high assurance that you get the correct code. It is an append-only public log of all unique Go modules/versions ever requested through "go get". It is just like certificate transparency logs for TLS certificates.'),
			dom.p('GopherWatch follows the modules/versions appended to the Go sum database. You can subscribe to modules. GopherWatch sends you an email whenever a new matching module/version appears in the append-only log.'),
			dom.h2('Recent modules'),
			dom.p(dom.span('Prerelease versions ', attr.title('semver version with a dash, such as v1.2.3-20060102150405-652ceb448533')), ' and apparent mirrors not shown.'),
			dom.table(
				dom._class('recents'), dom._class('mono'),
				dom.thead(
					dom.tr(
						dom.th('Module', attr.title('Repo URLs are guesses and may be wrong.')),
						dom.th('Version', attr.title('Tag URLs are guesses and may be wrong.')),
						dom.th('Age'),
						dom.th('Docs', attr.title('Doc URLs are guesses and may be wrong.')),
					),
				),
				recentsElem,
			),
			dom.br(),
			dom.h2('Get started'),
			dom.p(
				dom.clickbutton('Create account', function click() {
					signup(home.SignupNote)
				}),
				' Do it.',
			),
			dom.h2('FAQ'),
			dom.dl(
				dom.dt(dom.h3("How does this compare to other mechanism to stay updated on modules?")),
				dom.dd(
					dom.p('You have several options for tracking dependencies for a Go project:'),
					dom.ul(
						dom.li('Just running "get get -u" to update dependencies to the latest versions.'),
						dom.li('You can find dependencies that really need to be upgraded with "govulncheck". It helpfully only mentions modules if you are using vulnerable code.'),
						dom.li('You could also "watch" a repository on e.g. github. But it\'ll be different for each "software forge". On github, it only works if "releases" are created. You cannot watch new tagged versions with the "watch" feature. Though you can watch tags using RSS. The point is, software forges are different, some do not help you.'),
					),
					dom.br(),
					dom.p('GopherWatch works regardless of where the software is "hosted". GopherWatch can also notify repositories that match a module prefix, e.g. all modules/versions in an organization, perhaps your own.'),
					dom.p('GopherWatch can not report on a module if it is never requested through the Go module proxy.'),
					dom.p('GopherWatch does not currently watch the depedencies of modules you are subscribed to. That could be a good next step: Each time a module version is released, fetch the new go.mod and start monitoring dependencies for new versions. Patches welcome!'),
				),
			),
			home.Note ? [
				dom.h2('Notes'),
				dom.pre(dom._class('mono'), style({whiteSpace: 'pre-wrap', padding: '1em', backgroundColor: '#eee', borderRadius: '.25em'}), home.Note),
			] : [],
			dom.h2('About'),
			dom.p('The GopherWatch code is available at ', dom.a(attr.href('https://github.com/mjl-/gopherwatch'), 'github.com/mjl-/gopherwatch'), '. Bug reports/feedback/patches welcome. This is version ', home.Version, ', ', home.GoVersion, ' on ', home.GoOS, '/', home.GoArch, '.'),
		)
	)
}

const verifysignup = async (verifyToken: string) => {
	let fieldset: HTMLFieldSetElement
	let email: HTMLInputElement
	let password: HTMLInputElement

	const prepToken = await client.Prep()
	const emailAddress = await client.SignupEmail(prepToken, verifyToken)

	const page = dom.div(dom._class('page'),
		dom.h1('Verify new account'),
		dom.p('Set a password for future logins.'),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.stopPropagation()
				e.preventDefault()

				await check(fieldset, async () => {
					const prepToken = await client.Prep()
					const csrfToken = await client.VerifySignup(prepToken, verifyToken, email.value, password.value)
					localStorageSet("gopherwatchcsrftoken", csrfToken)
					reinitClient()
					signupverified()
				})
			},
			fieldset=dom.fieldset(
				dom.label(
					'Email address',
					dom.div(email=dom.input(attr.type('email'), attr.required(''), attr.value(emailAddress), attr.disabled(''))),
				),
				dom.label(
					'Password',
					dom.div(password=dom.input(attr.type('password'), attr.required(''))),
					dom.div(dom._class('explain'), 'Use a unique, random password, possibly managed in a password manager.'),
				),
				dom.br(),
				dom.div(dom.submitbutton('Verify account')),
			),
		),
	)
	dom._kids(document.body, page)
	// No focus, triggers popover on firefox.
	// password.focus()
}

const signupverified = () => {
	dom._kids(document.body,
		dom.div(dom._class('page'),
			dom.h1('Account verified'),
			dom.p("Great, your account has been verified. We've logged you in."),
			dom.p("Continue to ", dom.a(attr.href('#overview'), 'overview'), '.')
		),
	)
}

const logintoken = async (loginToken: string) => {
	const page = dom.div(dom._class('page'),
		dom.p("Redeeming login token for session..."),
		dom.p(dom.a(attr.href('#'), 'To home'))
	)
	dom._kids(document.body, page)

	const prepToken = await client.Prep()
	const csrfToken = await client.Redeem(prepToken, loginToken)
	localStorageSet("gopherwatchcsrftoken", csrfToken)
	reinitClient()
	window.location.hash = '#overview'
}

const resetpassword = async (resetToken: string) => {
	let fieldset: HTMLFieldSetElement
	let email: HTMLInputElement
	let password: HTMLInputElement

	dom._kids(document.body,
		dom.div(dom._class('page'),
			dom.h1('New password'),
			dom.form(
				async function submit(e: SubmitEvent) {
					e.preventDefault()
					e.stopPropagation()

					await check(fieldset, async () => {
						const prepToken = await client.Prep()
						await client.ResetPassword(prepToken, email.value, password.value, resetToken)
						passwordReset()
					})
				},
				fieldset=dom.fieldset(
					dom.label(
						'Email address',
						dom.div(email=dom.input(attr.type('email'), attr.required(''))),
					),
					dom.label(
						'Password',
						dom.div(password=dom.input(attr.type('password'), attr.required(''))),
					),
					dom.div(dom.submitbutton('Set new password')),
				),
			),
		)
	)
	email.focus()
}

const passwordReset = () => {
	dom._kids(document.body,
		dom.div(dom._class('page'),
			dom.h1('Password has been reset'),
			dom.p("Success! You'll have to login now. To ", dom.a(attr.href('#overview'), 'overview'), '.'),
		),
	)
}

const route0 = async () => {
	const h = decodeURIComponent(window.location.hash.substring(1) || '')
	const t = h.split('/')
	if (h === '') {
		await home()
	} else if (h === 'overview') {
		await overview()
	} else if (t[0] === 'verifysignup' && t.length === 2) {
		await verifysignup(t[1])
	} else if (t[0] === 'login' && t.length === 2) {
		await logintoken(t[1])
	} else if (t[0] === 'resetpassword' && t.length === 2) {
		await resetpassword(t[1])
	} else {
		// Unknown location, back to home.
		window.location.hash = ''
	}
}

const route = async () => {
	try {
		await route0()
	} catch (err) {
		window.alert('Error loading page: ' + errmsg(err))
	}
}

const init = () => {
	window.addEventListener('hashchange', route)
	route()
}

window.addEventListener('load', init)
