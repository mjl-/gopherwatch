const errmsg = (err: unknown) => ''+((err as any).message || '(no error message)')

const zindexes = {
	popup: '1',
	login: '2',
}

const check = async <T>(elem: { disabled: boolean }, fn: () => Promise<T>): Promise<T> => {
	elem.disabled = true
        document.body.classList.toggle('loading', true)
	try {
		return await fn()
	} catch (err) {
		console.log('error', err)
		window.alert('Error: ' + errmsg(err))
		throw err
	} finally {
		document.body.classList.toggle('loading', false)
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
		document.body.classList.toggle('loading', false)
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

const subscriptionPopup = (sub: api.Subscription, subscriptions: api.Subscription[], hookconfigs: api.HookConfig[], render: () => void) => {
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
	let webhookconfig: HTMLSelectElement
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
					HookConfigID: parseInt(webhookconfig.value),
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
							HookConfigID: parseInt(webhookconfig.value),
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
					sub.ID ? [] : dom.div(
						style({textAlign: 'right'}),
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
					),
					dom.label(
						style({display: 'flex', justifyContent: 'space-between'}),
						dom.div('Module '),
						dom.a(attr.href('#'), style({fontSize: '.9em'}), 'Presets for new Go toolchains', attr.title('Presets to get a notification when a new Go toolchain is released.'), function click(e: MouseEvent) {
							e.preventDefault()
							module.value = 'golang.org/toolchain'
							belowModule.checked = false
							olderVersions.checked = true
							prerelease.checked = true
							pseudo.checked = false
						}),
					),
					dom.div(
						module=dom.input(attr.required(''), attr.value(sub.Module), function change() {
							// User may input a URL, better fix it for them instead of making the user fix it.
							module.value = module.value.replace(/^https?:\/\//, '')
							module.value = module.value.replace(/\/*$/, '')
						}),
						dom.div(dom._class('explain'), 'Enter a single module as you would use in a Go import statement.', dom.br(), 'Example: github.com/mjl-/gopherwatch, github.com/mjl- or golang.org.'),
					),
				),
				dom.br(),
				dom.b('Notify about ...'),
				dom.label(belowModule=dom.input(attr.type('checkbox'), sub.BelowModule ? attr.checked('') : []), ' ', dom.span('Sub modules', attr.title('E.g. if subscribed to github.com/mjl-, whether to match github.com/mjl-/gopherwatch.'))),
				dom.label(olderVersions=dom.input(attr.type('checkbox'), sub.OlderVersions ? attr.checked('') : []), ' ', dom.span('Older versions than already seen', attr.title('Can happen when an old version (tag) is requested through the Go module proxy after a later tag, not uncommon after forking a repository and pushing all historic tags.'))),
				dom.label(prerelease=dom.input(attr.type('checkbox'), sub.Prerelease ? attr.checked('') : []), ' Prereleases such as v1.2.3-beta1'),
				dom.label(
					pseudo=dom.input(
						attr.type('checkbox'),
						sub.Pseudo ? attr.checked('') : [],
						function change() {
							if (pseudo.checked) {
								prerelease.checked = true
							}
						},
					),
					' Pseudo versions, such as v0.0.0-20240222094833-a1bd684a916b'),
					attr.title('Pseudo versions are also prereleases. In order to match a pseudoversion, prerelease must also be checked.'),
				dom.br(),
				dom.label(
					'Comment',
					// explicit String to prevent special scriptswitch handling
					comment=dom.textarea(new String(sub.Comment)),
				),
				dom.br(),
				dom.label(
					'Delivery method',
					dom.div(
						webhookconfig=dom.select(
							dom.option('Email', attr.value('0')),
							hookconfigs.map(hc => dom.option('Webhook '+hc.Name, attr.value(''+hc.ID), sub.HookConfigID === hc.ID ? attr.selected('') : [])),
						),
					),
				),
				dom.br(),
				dom.div(submitbtn=dom.submitbutton(sub.ID ? 'Save subscription' : 'Add subscription')),
			),
		)
	)
	module.focus()
}

const hookconfigPopup = (hc: api.HookConfig, hookconfigs: api.HookConfig[], render: () => void) => {
	let fieldset: HTMLFieldSetElement
	let name: HTMLInputElement
	let url: HTMLInputElement
	let headers: HTMLTextAreaElement
	let disabled: HTMLInputElement

	const close = popup(
		dom.h1(hc.ID ? 'Edit webhook config' : 'New webhook config'),
		dom.form(
			async function submit(e: SubmitEvent) {
				e.stopPropagation()
				e.preventDefault()

				await check(fieldset, async () => {
					const parsedHeaders = headers.value.split('\n')
						.map(s => s.split(':', 2))
						.filter(tup => tup.length === 2)
						.map(tup => [tup[0].trim(), tup[1].trim()])
						.filter(tup => tup[0] && tup[1])

					let nhc: api.HookConfig = {
						ID: hc.ID,
						UserID: hc.UserID,
						Name: name.value,
						URL: url.value,
						Headers: parsedHeaders,
						Disabled: disabled.checked,
					}

					if (hc.ID) {
						await client.HookConfigSave(nhc)
						hookconfigs.splice(hookconfigs.indexOf(hc), 1, nhc)
					} else {
						const xhc = await client.HookConfigAdd(nhc)
						hookconfigs.push(xhc)
					}
					render()
					close()
				})
			},
			fieldset=dom.fieldset(
				dom.label(
					'Name',
					name=dom.input(attr.required(''), attr.value(hc.Name)),
					dom.div(dom._class('explain'), 'Short unique name to identify webhook config.'),
				),
				dom.label(
					'URL',
					url=dom.input(attr.required(''), attr.value(hc.URL)),
					dom.div(
						dom._class('explain'),
						'URL to POST JSON body with updates to. ',
						dom.a(attr.href('#'), 'Details', function click(e: MouseEvent) {
							e.preventDefault()
							popup(
								style({maxWidth: '50em'}),
								dom.h1('Webhook HTTP requests'),
								dom.p('The request is a POST with a JSON body with the fields "Module", "Version", "Discovered" (timestamp) and "LogRecordID" (record ID in the sum database). More fields will likely be added in the future, so you should expect and allow for new fields to appear.'),
								dom.h2('Example JSON body'),
								dom.pre(dom._class('mono'), style({padding: '1em', backgroundColor: '#eee', borderRadius: '.5em'}), JSON.stringify({Module: 'github.com/mjl-/gopherwatch', Version: 'v0.0.1', Discovered: '2024-03-14T10:21:45.159Z', LogRecordID: 23637553}, undefined, '\t')),
								dom.br(),
								dom.p('Requests have to finish in 30 seconds. At most 256 bytes of the response is read. Any 2xx response status code is considered success. Redirects are followed. Any other response status code is considered an error and a retry is scheduled. Retries are scheduled with expontential backoff, starting at 7.5 minutes, then 15 minutes, 30 minutes, etc. Up to 9 retries, the last interval is 16 hours. However, a response status code of "403 forbidden" prevents further retries. If a "429 Too many requests" response is received for a webhook config, no new request is made for one minute after that response.'),
								dom.p('If deliveries keep failing (after retries), the webhook config is disabled: If the 10 most recent deliveries all failed, or if all of the deliveries of the past week failed (and there were at least 2). You can manually enable the webhook config again.'),
							)
						}),
					),
				),
				dom.br(),
				dom.label(
					'Headers',
					headers=dom.textarea(
						new String(
							(hc.Headers || []).map(tup => ((tup || [])[0])+': '+((tup || [])[1] || '')).join('\n')),
						attr.rows(''+(Math.max(5, (hc.Headers || []).length))),
					),
					dom.div(dom._class('explain'), 'Add custom headers to the request. Specify them in the form "key: value", one per line. Empty and malformed lines are removed, whitespace around keys and values is trimmed. Headers User-Agent and Content-Type are automatically set in all outgoing requests.'),
				),
				dom.br(),
				dom.label(
					disabled=dom.input(attr.type('checkbox'), hc.Disabled ? attr.checked('') : []),
					' Disabled, no new webhook calls are made',
				),
				dom.br(),
				dom.div(dom.submitbutton(hc.ID ? 'Save webhook config' : 'Add webhook config')),
			),
		)
	)
	name.focus()
}

const hookPopup = (rh: api.UpdateHook) => {
	// todo: show curl request that is equivalent to what we do. to help with debugging.

	const h = rh.Hook
	popup(
		dom.h1('Webhook delivery'),
		dom.div('Queued on ', h.Queued.toString(), '.'),
		dom.div('For module ', rh.Update.Module, ', version ', rh.Update.Version, '.'),
		dom.div('HTTP POST to ', h.URL, '.'),

		dom.h2('Results'),
		dom.table(
			dom.thead(
				dom.tr(
					dom.th('Start'),
					dom.th('Duration'),
					dom.th('Status'),
					dom.th('Error'),
					dom.th('Response'),
				),
			),
			dom.tbody(
				(h.Results || []).map(r => dom.tr(
					dom.td(age(r.Start), ' ago'),
					dom.td(''+r.DurationMS+'ms'),
					dom.td('' + (r.StatusCode || '-')),
					dom.td(r.Error),
					dom.td(r.Response),
				)),
			),
		),
	)
}

const overview = async () => {
	const overview = await client.Overview()
	let subscriptions: api.Subscription[] = overview.Subscriptions || []
	let hookconfigs: api.HookConfig[] = overview.HookConfigs || []
	let moduleUpdates: api.ModuleUpdateURLs[] = overview.ModuleUpdates || []
	let recentHooks: api.UpdateHook[] = overview.RecentHooks || []

	let substbody: HTMLElement
	let hookconfigstbody: HTMLElement
	let moduptbody: HTMLElement
	let hookstbody: HTMLElement

	// todo: SSE for updates to email/webhook deliveries in web interface.

	const render = () => {
		const nsubs = dom.tbody(
			subscriptions.length === 0 ? dom.tr(dom.td(attr.colspan('8'), 'No subscriptions yet, add the first one!')) : [],
			subscriptions.map(sub => {
				const row = dom.tr(
					(overview.SkipModulePaths || []).includes(sub.Module) ? [
						attr.title('Module will not match because it is on the list of skipped module paths:\n'+(overview.SkipModulePaths || []).join('\n')),
						style({color: '#888'})
					] : [],
					dom.td(
						sub.Module,
					),
					dom.td(sub.BelowModule ? 'Yes' : 'No'),
					dom.td(sub.OlderVersions ? 'Yes' : 'No'),
					dom.td(sub.Prerelease ? 'Yes' : 'No'),
					dom.td(sub.Pseudo ? 'Yes' : 'No'),
					dom.td(sub.HookConfigID === 0 ? 'Email' : 'Webhook '+hookconfigs.find(hc => hc.ID === sub.HookConfigID)!.Name),
					dom.td(style({maxWidth: '40em'}), sub.Comment),
					dom.td(
						dom.clickbutton('Edit', function click() { subscriptionPopup(sub, subscriptions, hookconfigs, render) }), ' ',
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
			moduleUpdates.length === 0 ? dom.tr(dom.td(attr.colspan('6'), 'No module updates.')) : [],
			moduleUpdates.map(modup => {
				const link = (anchor: string, url: string) => dom.a(attr.href(url), anchor, attr.rel('noopener'))
				const row = dom.tr(
					dom.td(link(modup.Module, modup.RepoURL || 'https://'+modup.Module)),
					dom.td(modup.TagURL ? link(modup.Version, modup.TagURL) : modup.Version),
					dom.td(modup.Discovered ? age(modup.Discovered) : []),
					dom.td(modup.DocURL ? link('Doc', modup.DocURL) : []),
					dom.td(modup.HookConfigID ? ('Webhook '+(hookconfigs.find(hc => hc.ID === modup.HookConfigID)?.Name || '(not found)')) : 'Email'),
					dom.td(modup.MessageID ? 'Yes' : 'No'),
				)
				return row
			}),
		)
		moduptbody.replaceWith(nmodups)
		moduptbody = nmodups

		const nhookconfigs = dom.tbody(
			hookconfigs.length === 0 ? dom.tr(dom.td(attr.colspan('4'), 'No webhook configs yet, add the first one!')) : [],
			hookconfigs.map(hc => {
				const row = dom.tr(
					dom.td(hc.Name),
					dom.td(hc.URL),
					dom.td(hc.Disabled ? 'Yes' : 'No'),
					dom.td(
						dom.clickbutton('Edit', function click() { hookconfigPopup(hc, hookconfigs, render) }), ' ',
						dom.clickbutton('Remove', async function click(e: MouseEvent) {
							if (!window.confirm('Are you sure?')) {
								return
							}
							await check(e.target! as HTMLButtonElement, async () => {
								await client.HookConfigRemove(hc.ID)
								hookconfigs.splice(hookconfigs.indexOf(hc), 1)

								for (let i = 0; i < recentHooks.length;) {
									if (recentHooks[i].Hook.HookConfigID === hc.ID) {
										recentHooks.splice(i, 1)
									} else {
										i++
									}
								}

								render()
							})
						}),
					),
				)
				return row
			}),
		)
		hookconfigstbody.replaceWith(nhookconfigs)
		hookconfigstbody = nhookconfigs

		const nhooks = dom.tbody(
			recentHooks.length === 0 ? dom.tr(dom.td(attr.colspan('7'), 'No webhook calls yet!')) : [],
			recentHooks.map(rh => {
				const h = rh.Hook
				let lastResult: api.HookResult | undefined
				if (h.Results && h.Results.length > 0) {
					lastResult = h.Results[h.Results.length-1]
				}
				const row = dom.tr(
					dom.td(hookconfigs.find(hc => hc.ID === h.HookConfigID)?.Name || ''),
					dom.td(rh.Update.Module),
					dom.td(rh.Update.Version),
					dom.td(''+h.Attempts),
					dom.td(h.Done ? '-' : age(h.NextAttempt, true)),
					dom.td(
						!lastResult ? '-' : [
							''+(lastResult.StatusCode || ''),
							' ',
							lastResult.Error,
						],
					),
					dom.td(
						dom.clickbutton('Results', (h.Results || []).length === 0 ? attr.disabled('') : [], function click() {
							hookPopup(rh)
						}), ' ',
						dom.clickbutton('Cancel', h.Done ? attr.disabled('') : [], async function click(e: MouseEvent) {
							await check(e.target! as HTMLButtonElement, async () => {
								const nh = await client.HookCancel(h.ID)
								recentHooks.splice(recentHooks.indexOf(rh), 1, {Update: rh.Update, Hook: nh})
								render()
							})
						}), ' ',
						dom.clickbutton('Kick', attr.title('Schedule next attempt as soon as possible'), h.Done ? attr.disabled('') : [], async function click(e: MouseEvent) {
							await check(e.target! as HTMLButtonElement, async () => {
								const nh = await client.HookKick(h.ID)
								recentHooks.splice(recentHooks.indexOf(rh), 1, {Update: rh.Update, Hook: nh})
								render()
							})
						}),
					),
				)
				return row
			}),
		)
		hookstbody.replaceWith(nhooks)
		hookstbody = nhooks
	}

	let intervalFieldset: HTMLFieldSetElement
	let interval: HTMLSelectElement

	const page = dom.div(
		dom._class('page'), dom._class('overview'),
		dom.div(
			style({display: 'flex', justifyContent: 'space-between'}),
			dom.div(
				dom.p('← ', dom.a(attr.href('#'), 'Home')),
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
					HookConfigID: 0,
				}
				subscriptionPopup(nsub, subscriptions, hookconfigs, render)
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
				dom.th('Delivery method'),
				dom.th('Comment'),
				dom.th('Action'),
			),
			substbody=dom.tbody(),
		),
		dom.br(),

		dom.div(
			dom.h2(style({display: 'inline-block'}), 'Webhook configs'), ' ',
			dom.clickbutton('Add', function click() {
				const nhc: api.HookConfig = {
					ID: 0,
					UserID: 0,
					Name: '',
					URL: '',
					Headers: [],
					Disabled: false
				}
				hookconfigPopup(nhc, hookconfigs, render)
			}),
		),
		dom.br(),
		dom.table(
			dom.tr(
				dom.th('Name'),
				dom.th('URL'),
				dom.th('Disabled'),
				dom.th('Action'),
			),
			hookconfigstbody=dom.tbody(),
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
									await client.SubscribeSet(true, overview.MetaUnsubscribed)
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
									await client.SubscribeSet(false, overview.UpdatesUnsubscribed)
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
				dom.th('Age'),
				dom.th('Docs', attr.title('Doc URLs are guesses and may be wrong.')),
				dom.th('Delivery method'),
				dom.th('Notified by email'),
			),
			moduptbody=dom.tbody(),
		),
		dom.br(),

		dom.h2('Webhook deliveries'),
		dom.table(
			dom.tr(
				dom.th('Webhook config'),
				dom.th('Module'),
				dom.th('Version'),
				dom.th('Attempts'),
				dom.th('Next attempt'),
				dom.th('Last result'),
				dom.th('Action'),
			),
			hookstbody=dom.tbody(),
		),
		dom.br(),

		dom.h2('History'),
		dom.p('Changes to your account over time, from recent to old.'),
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
			dom.p(dom.span("If all is well", attr.title('If you already have an account with essentially the same email address (wildcards removed, etc), you can not create another account via the website and we actually did not send you an email. You can only sign up with those similar addresses through a signup email.')), ", we've sent an email to ", dom.b(email), " with a confirmation link."),
			dom.p("If the email is not coming in, don't forget to check your spam mailbox. Also, some mail servers employ 'grey listing', holding off first-time deliveries for up to half an hour."),
			dom.p("Go back ", dom.a(attr.href('#'), 'home', function click() { route() }), '.'),
		),
	)
}

const signup = (home: api.Home) => {
	let fieldset: HTMLFieldSetElement
	let email: HTMLInputElement | undefined

	dom._kids(document.body,
		dom.div(dom._class('page'),
			dom.p('← ', dom.a(attr.href('#'), 'Home', function click() { route() })),
			dom.h1('Create account'),
			home.SignupNote ? [
				dom.pre(dom._class('mono'), style({whiteSpace: 'pre-wrap', padding: '1em', backgroundColor: '#eee', borderRadius: '.25em'}), home.SignupNote),
				dom.br(),
			] : [],

			home.SignupEmailDisabled && home.SignupWebsiteDisabled ? dom.p('Signups are disabled at the moment, sorry.') : [],

			dom.div(dom._class('signupoptions'),
				home.SignupEmailDisabled ? [] : [
					dom.div(
						// Only show header if there is a choice.
						home.SignupWebsiteDisabled ? [] : dom.h2('Option 1: Signup through email (recommended option)'),
						dom.p('Send us an email with "signup for ', home.ServiceName, '" as the subject:'),
						dom.p(style({marginLeft: '3em'}), dom.a(attr.href('mailto:'+encodeURIComponent(home.SignupAddress)+'?subject='+encodeURIComponent('signup for '+home.ServiceName) + '&body='+encodeURIComponent('sign me up for gopherwatch!')), home.SignupAddress)),
						dom.p(`Any message body will do, it's ignored. You'll get a reply with a link to confirm and set a password, after which we'll automatically log you in. Easy.`),
						home.SignupWebsiteDisabled ? [] : dom.p("Sending us the first email ", dom.span("helps your junk filter realize we're good people.", attr.title(`Because our email address will be a known correspondent in your account. It may also prevent delays in delivery. Hopefully your junk filter will seize the opportunity! On top of that, it will also prevent us from being misused into sending messages to unsuspecting people, because we only reply to messages from legitimate senders (spf/dkim/dmarc-verified). For similar reasons, you can only sign up with wildcard email addresses (like user+$anything@domain) via email and not via the website.`))),
						dom.br(),
					),
				],

				home.SignupWebsiteDisabled ? [] : [
					dom.div(
						home.SignupEmailDisabled ? [] : dom.h2('Option 2: Signup through website (fallback option)'),
						dom.p('Please have a look at signing up with option 1 first.'),
						dom.form(
							async function submit(e: SubmitEvent) {
								e.stopPropagation()
								e.preventDefault()

								await check(fieldset, async () => {
									const prepToken = await client.Prep()
									await client.Signup(prepToken, email!.value.trim())
									signedup(email!.value.trim())
								})
							},
							fieldset=dom.fieldset(
								dom.label(
									style({display: 'inline'}),
									'Email address', ' ',
									email=dom.input(attr.type('email'), attr.required('')),
								),
								' ',
								dom.submitbutton('Create account'),
							),
							dom.p("We'll send you an email with a confirmation link."),
						)
					),
				],
			),
		)
	)
	if (email && home.SignupEmailDisabled) {
		email.focus()
	}
}

const age = (date: Date, future?: boolean) => {
	const nowSecs = new Date().getTime()/1000
	let t = nowSecs - date.getTime()/1000
	if (future) {
		t = -t
	}
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
			dom.p('In Go, you use ', dom.span('"go get"', attr.title('Or related commands, such as "go install", "go mod tidy" and more')), ' to download Go modules to use as a dependency. Retrieving a module is done through the ', dom.a(attr.href('https://proxy.golang.org'), attr.rel('noopener'), 'Go module proxy'), ', which adds all module versions to the ', dom.a(attr.href('https://sum.golang.org'), attr.rel('noopener'), 'Go checksum database'), ', a ', dom.a(attr.href('https://research.swtch.com/tlog'), attr.rel('noopener'), 'transparency log'), ': A signed, append-only public log containing module versions along with a hash of their contents, providing high assurance that everyone requesting a module gets the same code. It is just like certificate transparency logs for TLS certificates.'),
			dom.p('GopherWatch follows the modules/versions appended to the Go sum database. You can subscribe to modules. GopherWatch sends you an email whenever a new matching module/version appears in the append-only log.'),
			dom.h2('Recent modules'),
			dom.p(dom.span('Prerelease versions ', attr.title('semver version with a dash, such as v1.2.3-20060102150405-652ceb448533')), ' and ', dom.span('apparent mirrors', attr.title((home.SkipModulePrefixes || []).join('\n'))), ' not shown.'),
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
					signup(home)
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
		document.body.classList.toggle('loading', true)
		await route0()
	} catch (err) {
		window.alert('Error loading page: ' + errmsg(err))
	} finally {
		document.body.classList.toggle('loading', false)
	}
}

const init = () => {
	window.addEventListener('hashchange', route)
	route()
}

window.addEventListener('load', init)
