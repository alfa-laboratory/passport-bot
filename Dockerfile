FROM groovy
ADD passport-slack.groovy .
EXPOSE 5051

CMD groovy passport-slack.groovy