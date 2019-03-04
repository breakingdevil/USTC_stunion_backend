#!/usr/bin/ruby

file = ARGV[1] || 'analysis.txt'
out = ARGV[2] || 'analysis.csv'
started = false

File.open file, 'r' do |fin|
  File.open out, 'w' do |fout|
    fin.each do |line|
      /^Query results for ".*(\d+-\d+)\.sql"/.match line do |match|
        if !started
          started = true
        else
          fout.write "\n"
        end
        fout.write match[1]
      end

      /^Query "(.*)\.sql"/.match line do |match|
        has_content = false
        case m[1]
        when 'user_count'
          mode = 1
        when 'user_type'
          mode = 2
        when 'wish_status'
          mode = 3
        when 'love_count'
          mode = 4
        else
          fail TypeError, 'Unrecognized query'
        end
      end

      /^[A-Z][A-Za-z]+\t[A-Z][A-Za-z]+/.match line do |match|
        has_content = true
      end
    end
  end
end
