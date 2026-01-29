package com.reviewdemo.reviewdemo.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletContext;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Scope("request")
public class ToolsController {
	private static final Logger logger = LogManager.getLogger("Reviewdemo:ToolsController");

	@Autowired
	ServletContext context;

	@RequestMapping(value = "/tools", method = RequestMethod.GET)
	public String tools() {
		return "tools";
	}

	@RequestMapping(value = "/tools", method = RequestMethod.POST)
	public String tools(@RequestParam(value = "host", required = false) String host, @RequestParam(value = "fortunefile", required = false) String fortuneFile, Model model) {
		model.addAttribute("ping", host != null ? ping(host) : "");

		if (fortuneFile == null) {
			fortuneFile = "literature";
		}
		model.addAttribute("fortunes", fortune(fortuneFile));

		return "tools";
	}

	@RequestMapping(value = "/tools/echo", method = RequestMethod.GET, produces = "text/plain;charset=UTF-8")
	@ResponseBody
	public String echo(
			@RequestParam(value = "times", required = true) String times,
			@RequestParam(value = "msg", required = false) String msg) {
		if (msg == null) {
			msg = "";
		}

		int count = Integer.parseInt(times);
		StringBuilder output = new StringBuilder();
		for (int i = 0; i < count; i++) {
			output.append(msg);
		}

		return output.toString();
	}

	private String ping(String host) {
		String output = "";
		Process proc;

		logger.info("Pinging: " + host);

		try {
			proc = Runtime.getRuntime().exec(new String[] { "bash", "-c", "ping -c1 " + host });

			proc.waitFor(5, TimeUnit.SECONDS);
			InputStreamReader isr = new InputStreamReader(proc.getInputStream());
			BufferedReader br = new BufferedReader(isr);

			String line;

			while ((line = br.readLine()) != null) {
				output += line + "\n";
			}

			logger.info(proc.exitValue());
		} catch (IOException ex) {
			logger.error(ex);
		} catch (InterruptedException ex) {
			logger.error(ex);
		}

		return output;
	}

	private String fortune(String fortuneFile) {
		String cmd = "/bin/fortune " + fortuneFile;

		String output = "";
		Process proc;
		try {
			proc = Runtime.getRuntime().exec(new String[] { "bash", "-c", cmd });

			proc.waitFor(5, TimeUnit.SECONDS);
			InputStreamReader isr = new InputStreamReader(proc.getInputStream());
			BufferedReader br = new BufferedReader(isr);

			String line;

			while ((line = br.readLine()) != null) {
				output += line + "\n";
			}
		} catch (IOException ex) {
			logger.error(ex);
		} catch (InterruptedException ex) {
			logger.error(ex);
		}

		return output;
	}
}
